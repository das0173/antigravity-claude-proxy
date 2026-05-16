/**
 * API Keys Module - Multi-user API key management with SQLite
 * 
 * Features:
 * - Window-based rate limiting (reset every X hours)
 * - RPM (requests per minute) limiting
 * - Max concurrent devices per key
 * - Full key storage for admin viewing
 * - Notes, webhook URL support
 */

import Database from 'better-sqlite3';
import crypto from 'crypto';
import path from 'path';
import os from 'os';
import fs from 'fs';
import { logger } from '../utils/logger.js';

// Database location - uses DATA_DIR for Railway Volume persistence
const CONFIG_DIR = process.env.DATA_DIR || path.join(os.homedir(), '.config', 'antigravity-proxy');
const DB_PATH = path.join(CONFIG_DIR, 'api-keys.db');

// Ensure config directory exists
if (!fs.existsSync(CONFIG_DIR)) {
    fs.mkdirSync(CONFIG_DIR, { recursive: true });
}

let db;

/**
 * Initialize SQLite database and create tables
 */
function initDB() {
    if (db) return db;

    db = new Database(DB_PATH);
    db.pragma('journal_mode = WAL');
    db.pragma('foreign_keys = ON');

    db.exec(`
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_hash TEXT NOT NULL UNIQUE,
            key_prefix TEXT NOT NULL,
            key_full TEXT NOT NULL,
            name TEXT NOT NULL,
            notes TEXT DEFAULT '',
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            expires_at TEXT,
            
            -- Window-based rate limiting
            window_hours INTEGER NOT NULL DEFAULT 0,
            max_requests_per_window INTEGER NOT NULL DEFAULT 120,
            requests_in_window INTEGER NOT NULL DEFAULT 0,
            last_window_reset TEXT,
            
            -- Monthly and daily limits
            max_requests_per_day INTEGER NOT NULL DEFAULT 0,
            max_requests_per_month INTEGER NOT NULL DEFAULT 0,
            requests_today INTEGER NOT NULL DEFAULT 0,
            requests_this_month INTEGER NOT NULL DEFAULT 0,
            
            -- RPM (requests per minute)
            max_rpm INTEGER NOT NULL DEFAULT 0,
            rpm_requests TEXT DEFAULT '[]',
            
            -- Device/session limiting
            max_devices INTEGER NOT NULL DEFAULT 1,
            active_devices TEXT DEFAULT '{}',
            
            -- Webhook
            webhook_url TEXT DEFAULT '',
            
            -- Counters
            total_requests INTEGER NOT NULL DEFAULT 0,
            last_used TEXT,
            last_reset_day TEXT,
            last_reset_month TEXT
        );

        CREATE TABLE IF NOT EXISTS api_key_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_id INTEGER NOT NULL,
            model TEXT,
            endpoint TEXT,
            status_code INTEGER,
            device_id TEXT,
            timestamp TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (key_id) REFERENCES api_keys(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
        CREATE INDEX IF NOT EXISTS idx_api_key_logs_key_id ON api_key_logs(key_id);
        CREATE INDEX IF NOT EXISTS idx_api_key_logs_timestamp ON api_key_logs(timestamp);
    `);

    // Migration: add new columns if they don't exist (for existing installs)
    const columns = db.prepare("PRAGMA table_info(api_keys)").all().map(c => c.name);
    const migrations = {
        'key_full': "ALTER TABLE api_keys ADD COLUMN key_full TEXT DEFAULT ''",
        'notes': "ALTER TABLE api_keys ADD COLUMN notes TEXT DEFAULT ''",
        'window_hours': "ALTER TABLE api_keys ADD COLUMN window_hours INTEGER NOT NULL DEFAULT 0",
        'max_requests_per_window': "ALTER TABLE api_keys ADD COLUMN max_requests_per_window INTEGER NOT NULL DEFAULT 120",
        'requests_in_window': "ALTER TABLE api_keys ADD COLUMN requests_in_window INTEGER NOT NULL DEFAULT 0",
        'last_window_reset': "ALTER TABLE api_keys ADD COLUMN last_window_reset TEXT",
        'max_rpm': "ALTER TABLE api_keys ADD COLUMN max_rpm INTEGER NOT NULL DEFAULT 0",
        'rpm_requests': "ALTER TABLE api_keys ADD COLUMN rpm_requests TEXT DEFAULT '[]'",
        'max_devices': "ALTER TABLE api_keys ADD COLUMN max_devices INTEGER NOT NULL DEFAULT 1",
        'active_devices': "ALTER TABLE api_keys ADD COLUMN active_devices TEXT DEFAULT '{}'",
        'webhook_url': "ALTER TABLE api_keys ADD COLUMN webhook_url TEXT DEFAULT ''"
    };
    for (const [col, sql] of Object.entries(migrations)) {
        if (!columns.includes(col)) {
            try { db.exec(sql); } catch (e) { /* ignore */ }
        }
    }

    logger.info('[API Keys] Database initialized');
    return db;
}

/**
 * Hash an API key using SHA-256
 */
function hashKey(key) {
    return crypto.createHash('sha256').update(key).digest('hex');
}

/**
 * Generate a new API key
 * Format: ag-<32 hex chars>
 */
function generateKeyString() {
    const random = crypto.randomBytes(16).toString('hex');
    return `ag-${random}`;
}

/**
 * Generate a device ID from IP + User-Agent
 */
export function getDeviceId(req) {
    const ip = req.ip || req.connection?.remoteAddress || 'unknown';
    const ua = req.headers['user-agent'] || 'unknown';
    return crypto.createHash('md5').update(`${ip}::${ua}`).digest('hex').substring(0, 12);
}

/**
 * Check and reset counters if needed (daily, monthly, window)
 */
function resetCountersIfNeeded(keyRow) {
    const now = new Date();
    const today = now.toISOString().split('T')[0];
    const thisMonth = today.substring(0, 7);
    const database = initDB();
    
    // Daily reset
    if (keyRow.last_reset_day !== today) {
        database.prepare('UPDATE api_keys SET requests_today = 0, last_reset_day = ? WHERE id = ?').run(today, keyRow.id);
        keyRow.requests_today = 0;
        keyRow.last_reset_day = today;
    }

    // Monthly reset
    if (keyRow.last_reset_month !== thisMonth) {
        database.prepare('UPDATE api_keys SET requests_this_month = 0, last_reset_month = ? WHERE id = ?').run(thisMonth, keyRow.id);
        keyRow.requests_this_month = 0;
        keyRow.last_reset_month = thisMonth;
    }

    // Window reset
    if (keyRow.window_hours > 0 && keyRow.last_window_reset) {
        const lastReset = new Date(keyRow.last_window_reset);
        const hoursSinceReset = (now - lastReset) / (1000 * 60 * 60);
        if (hoursSinceReset >= keyRow.window_hours) {
            database.prepare('UPDATE api_keys SET requests_in_window = 0, last_window_reset = ? WHERE id = ?').run(now.toISOString(), keyRow.id);
            keyRow.requests_in_window = 0;
            keyRow.last_window_reset = now.toISOString();
        }
    }

    // Clean old RPM entries (older than 60 seconds)
    if (keyRow.max_rpm > 0) {
        try {
            const rpmRequests = JSON.parse(keyRow.rpm_requests || '[]');
            const oneMinuteAgo = now.getTime() - 60000;
            const filtered = rpmRequests.filter(ts => ts > oneMinuteAgo);
            if (filtered.length !== rpmRequests.length) {
                database.prepare('UPDATE api_keys SET rpm_requests = ? WHERE id = ?').run(JSON.stringify(filtered), keyRow.id);
                keyRow.rpm_requests = JSON.stringify(filtered);
            }
        } catch (e) { /* ignore parse errors */ }
    }

    // Clean stale devices (older than 30 minutes)
    try {
        const devices = JSON.parse(keyRow.active_devices || '{}');
        const thirtyMinAgo = now.getTime() - (30 * 60 * 1000);
        let changed = false;
        for (const [deviceId, lastSeen] of Object.entries(devices)) {
            if (lastSeen < thirtyMinAgo) {
                delete devices[deviceId];
                changed = true;
            }
        }
        if (changed) {
            database.prepare('UPDATE api_keys SET active_devices = ? WHERE id = ?').run(JSON.stringify(devices), keyRow.id);
            keyRow.active_devices = JSON.stringify(devices);
        }
    } catch (e) { /* ignore */ }

    return keyRow;
}

/**
 * Create a new API key
 */
export function createKey({ name, notes = '', maxRequestsPerWindow = 120, windowHours = 3, maxRequestsPerDay = 0, maxRequestsPerMonth = 0, maxRpm = 0, maxDevices = 1, expiresAt = null, webhookUrl = '' }) {
    const database = initDB();

    if (!name || typeof name !== 'string' || name.trim().length === 0) {
        throw new Error('Name is required');
    }

    const key = generateKeyString();
    const keyHash = hashKey(key);
    const keyPrefix = key.substring(0, 11) + '...';

    const now = new Date();
    const today = now.toISOString().split('T')[0];
    const thisMonth = today.substring(0, 7);

    const stmt = database.prepare(`
        INSERT INTO api_keys (key_hash, key_prefix, key_full, name, notes, max_requests_per_window, window_hours, max_requests_per_day, max_requests_per_month, max_rpm, max_devices, expires_at, webhook_url, last_reset_day, last_reset_month, last_window_reset)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const result = stmt.run(keyHash, keyPrefix, key, name.trim(), notes, maxRequestsPerWindow, windowHours, maxRequestsPerDay, maxRequestsPerMonth, maxRpm, maxDevices, expiresAt, webhookUrl, today, thisMonth, now.toISOString());

    logger.info(`[API Keys] Created key "${name}" (${keyPrefix}), ID: ${result.lastInsertRowid}`);

    return {
        id: result.lastInsertRowid,
        key,
        keyPrefix,
        name: name.trim(),
        enabled: true,
        createdAt: now.toISOString()
    };
}

/**
 * Validate an API key and check all limits
 */
export function validateKey(key, deviceId = null) {
    const database = initDB();

    if (!key || !key.startsWith('ag-')) {
        return { valid: false, error: 'Invalid key format' };
    }

    const keyHash = hashKey(key);
    let keyRow = database.prepare('SELECT * FROM api_keys WHERE key_hash = ?').get(keyHash);

    if (!keyRow) {
        return { valid: false, error: 'Invalid API key' };
    }

    if (!keyRow.enabled) {
        return { valid: false, error: 'API key is disabled' };
    }

    // Check expiration
    if (keyRow.expires_at) {
        const expiresAt = new Date(keyRow.expires_at);
        if (expiresAt < new Date()) {
            return { valid: false, error: 'API key has expired' };
        }
    }

    // Reset counters if needed
    keyRow = resetCountersIfNeeded(keyRow);

    // Check window limit
    if (keyRow.window_hours > 0 && keyRow.max_requests_per_window > 0) {
        if (keyRow.requests_in_window >= keyRow.max_requests_per_window) {
            // Calculate remaining time
            const lastReset = new Date(keyRow.last_window_reset);
            const nextReset = new Date(lastReset.getTime() + keyRow.window_hours * 60 * 60 * 1000);
            const minutesLeft = Math.ceil((nextReset - new Date()) / 60000);
            return { valid: false, error: `Window limit reached (${keyRow.max_requests_per_window}/${keyRow.window_hours}h). Resets in ${minutesLeft} min` };
        }
    }

    // Check daily limit
    if (keyRow.max_requests_per_day > 0 && keyRow.requests_today >= keyRow.max_requests_per_day) {
        return { valid: false, error: `Daily limit reached (${keyRow.max_requests_per_day}/day)` };
    }

    // Check monthly limit
    if (keyRow.max_requests_per_month > 0 && keyRow.requests_this_month >= keyRow.max_requests_per_month) {
        return { valid: false, error: `Monthly limit reached (${keyRow.max_requests_per_month}/month)` };
    }

    // Check RPM
    if (keyRow.max_rpm > 0) {
        const rpmRequests = JSON.parse(keyRow.rpm_requests || '[]');
        if (rpmRequests.length >= keyRow.max_rpm) {
            return { valid: false, error: `Rate limit: ${keyRow.max_rpm} requests per minute exceeded` };
        }
    }

    // Check device limit
    if (deviceId && keyRow.max_devices > 0) {
        const devices = JSON.parse(keyRow.active_devices || '{}');
        const isExistingDevice = devices[deviceId] !== undefined;
        const activeCount = Object.keys(devices).length;

        if (!isExistingDevice && activeCount >= keyRow.max_devices) {
            return { valid: false, error: `Device limit reached (${keyRow.max_devices} device${keyRow.max_devices > 1 ? 's' : ''} max). Reset devices or upgrade your plan.` };
        }
    }

    return {
        valid: true,
        keyInfo: {
            id: keyRow.id,
            keyPrefix: keyRow.key_prefix,
            name: keyRow.name,
            requestsInWindow: keyRow.requests_in_window,
            requestsToday: keyRow.requests_today,
            requestsThisMonth: keyRow.requests_this_month,
            maxRequestsPerWindow: keyRow.max_requests_per_window,
            maxRequestsPerDay: keyRow.max_requests_per_day,
            maxRequestsPerMonth: keyRow.max_requests_per_month,
            windowHours: keyRow.window_hours
        }
    };
}

/**
 * Increment usage counters for a key
 */
export function incrementUsage(keyId, logData = {}) {
    const database = initDB();
    const now = new Date();

    // Update all counters
    database.prepare(`
        UPDATE api_keys 
        SET requests_today = requests_today + 1, 
            requests_this_month = requests_this_month + 1, 
            requests_in_window = requests_in_window + 1,
            total_requests = total_requests + 1,
            last_used = datetime('now')
        WHERE id = ?
    `).run(keyId);

    // Update RPM tracking
    const keyRow = database.prepare('SELECT max_rpm, rpm_requests FROM api_keys WHERE id = ?').get(keyId);
    if (keyRow && keyRow.max_rpm > 0) {
        const rpmRequests = JSON.parse(keyRow.rpm_requests || '[]');
        rpmRequests.push(now.getTime());
        database.prepare('UPDATE api_keys SET rpm_requests = ? WHERE id = ?').run(JSON.stringify(rpmRequests), keyId);
    }

    // Update device tracking
    if (logData.deviceId) {
        const devRow = database.prepare('SELECT active_devices FROM api_keys WHERE id = ?').get(keyId);
        if (devRow) {
            const devices = JSON.parse(devRow.active_devices || '{}');
            devices[logData.deviceId] = now.getTime();
            database.prepare('UPDATE api_keys SET active_devices = ? WHERE id = ?').run(JSON.stringify(devices), keyId);
        }
    }

    // Log the request
    database.prepare(`
        INSERT INTO api_key_logs (key_id, model, endpoint, status_code, device_id)
        VALUES (?, ?, ?, ?, ?)
    `).run(keyId, logData.model || null, logData.endpoint || null, logData.statusCode || null, logData.deviceId || null);
}

/**
 * List all API keys (with full info for admin)
 */
export function listKeys() {
    const database = initDB();

    const keys = database.prepare(`
        SELECT * FROM api_keys ORDER BY created_at DESC
    `).all();

    return keys.map(key => {
        const resetKey = resetCountersIfNeeded(key);
        const devices = JSON.parse(resetKey.active_devices || '{}');
        const activeDeviceCount = Object.keys(devices).length;

        return {
            id: resetKey.id,
            keyPrefix: resetKey.key_prefix,
            keyFull: resetKey.key_full,
            name: resetKey.name,
            notes: resetKey.notes || '',
            enabled: !!resetKey.enabled,
            createdAt: resetKey.created_at,
            expiresAt: resetKey.expires_at,
            windowHours: resetKey.window_hours,
            maxRequestsPerWindow: resetKey.max_requests_per_window,
            requestsInWindow: resetKey.requests_in_window,
            maxRequestsPerDay: resetKey.max_requests_per_day,
            maxRequestsPerMonth: resetKey.max_requests_per_month,
            requestsToday: resetKey.requests_today,
            requestsThisMonth: resetKey.requests_this_month,
            maxRpm: resetKey.max_rpm,
            maxDevices: resetKey.max_devices,
            activeDevices: activeDeviceCount,
            webhookUrl: resetKey.webhook_url || '',
            totalRequests: resetKey.total_requests,
            lastUsed: resetKey.last_used,
            status: getKeyStatus(resetKey)
        };
    });
}

/**
 * Get key status string
 */
function getKeyStatus(keyRow) {
    if (!keyRow.enabled) return 'disabled';
    if (keyRow.expires_at && new Date(keyRow.expires_at) < new Date()) return 'expired';
    if (keyRow.window_hours > 0 && keyRow.max_requests_per_window > 0 && keyRow.requests_in_window >= keyRow.max_requests_per_window) return 'window_limit';
    if (keyRow.max_requests_per_day > 0 && keyRow.requests_today >= keyRow.max_requests_per_day) return 'daily_limit';
    if (keyRow.max_requests_per_month > 0 && keyRow.requests_this_month >= keyRow.max_requests_per_month) return 'monthly_limit';
    return 'active';
}

/**
 * Revoke (disable) an API key
 */
export function revokeKey(id) {
    const database = initDB();
    const result = database.prepare('UPDATE api_keys SET enabled = 0 WHERE id = ?').run(id);
    if (result.changes === 0) throw new Error(`Key ID ${id} not found`);
    logger.info(`[API Keys] Key ID ${id} revoked`);
}

/**
 * Enable an API key
 */
export function enableKey(id) {
    const database = initDB();
    const result = database.prepare('UPDATE api_keys SET enabled = 1 WHERE id = ?').run(id);
    if (result.changes === 0) throw new Error(`Key ID ${id} not found`);
    logger.info(`[API Keys] Key ID ${id} enabled`);
}

/**
 * Delete an API key permanently
 */
export function deleteKey(id) {
    const database = initDB();
    const result = database.prepare('DELETE FROM api_keys WHERE id = ?').run(id);
    if (result.changes === 0) throw new Error(`Key ID ${id} not found`);
    logger.info(`[API Keys] Key ID ${id} deleted permanently`);
}

/**
 * Update key settings
 */
export function updateKey(id, updates) {
    const database = initDB();

    const fieldMap = {
        name: 'name',
        notes: 'notes',
        maxRequestsPerWindow: 'max_requests_per_window',
        windowHours: 'window_hours',
        maxRequestsPerDay: 'max_requests_per_day',
        maxRequestsPerMonth: 'max_requests_per_month',
        maxRpm: 'max_rpm',
        maxDevices: 'max_devices',
        expiresAt: 'expires_at',
        enabled: 'enabled',
        webhookUrl: 'webhook_url'
    };

    const setClauses = [];
    const values = [];

    for (const [camelKey, snakeKey] of Object.entries(fieldMap)) {
        if (updates[camelKey] !== undefined) {
            setClauses.push(`${snakeKey} = ?`);
            values.push(updates[camelKey]);
        }
    }

    if (setClauses.length === 0) {
        throw new Error('No valid fields to update');
    }

    values.push(id);
    const sql = `UPDATE api_keys SET ${setClauses.join(', ')} WHERE id = ?`;
    const result = database.prepare(sql).run(...values);

    if (result.changes === 0) throw new Error(`Key ID ${id} not found`);
    logger.info(`[API Keys] Key ID ${id} updated`);
}

/**
 * Reset active devices for a key
 */
export function resetDevices(id) {
    const database = initDB();
    const result = database.prepare("UPDATE api_keys SET active_devices = '{}' WHERE id = ?").run(id);
    if (result.changes === 0) throw new Error(`Key ID ${id} not found`);
    logger.info(`[API Keys] Key ID ${id} devices reset`);
}

/**
 * Get usage statistics for a specific key
 */
export function getKeyUsage(id, days = 7) {
    const database = initDB();

    const key = database.prepare('SELECT * FROM api_keys WHERE id = ?').get(id);
    if (!key) throw new Error(`Key ID ${id} not found`);

    const logs = database.prepare(`
        SELECT model, endpoint, status_code, device_id, timestamp
        FROM api_key_logs
        WHERE key_id = ? AND timestamp >= datetime('now', ?)
        ORDER BY timestamp DESC
        LIMIT 500
    `).all(id, `-${days} days`);

    const byModel = {};
    const byDay = {};
    const byDevice = {};
    for (const log of logs) {
        const model = log.model || 'unknown';
        byModel[model] = (byModel[model] || 0) + 1;
        const day = log.timestamp.split('T')[0].split(' ')[0];
        byDay[day] = (byDay[day] || 0) + 1;
        if (log.device_id) {
            byDevice[log.device_id] = (byDevice[log.device_id] || 0) + 1;
        }
    }

    const devices = JSON.parse(key.active_devices || '{}');

    return {
        keyId: id,
        keyPrefix: key.key_prefix,
        name: key.name,
        totalRequests: key.total_requests,
        requestsToday: key.requests_today,
        requestsThisMonth: key.requests_this_month,
        requestsInWindow: key.requests_in_window,
        activeDevices: Object.keys(devices).length,
        maxDevices: key.max_devices,
        deviceDetails: devices,
        byModel,
        byDay,
        byDevice,
        recentLogs: logs.slice(0, 50)
    };
}

/**
 * Check if multi-key mode is enabled
 */
export function isMultiKeyEnabled() {
    const database = initDB();
    const count = database.prepare('SELECT COUNT(*) as cnt FROM api_keys').get();
    return count.cnt > 0;
}

/**
 * Get summary statistics
 */
export function getKeysSummary() {
    const database = initDB();

    const total = database.prepare('SELECT COUNT(*) as cnt FROM api_keys').get().cnt;
    const active = database.prepare('SELECT COUNT(*) as cnt FROM api_keys WHERE enabled = 1').get().cnt;
    const todayRequests = database.prepare('SELECT SUM(requests_today) as total FROM api_keys').get().total || 0;
    const monthRequests = database.prepare('SELECT SUM(requests_this_month) as total FROM api_keys').get().total || 0;

    return {
        totalKeys: total,
        activeKeys: active,
        disabledKeys: total - active,
        requestsToday: todayRequests,
        requestsThisMonth: monthRequests
    };
}

// Initialize on import
initDB();
