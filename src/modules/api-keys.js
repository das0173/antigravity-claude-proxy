/**
 * API Keys Module - Multi-user API key management with SQLite
 * 
 * Provides API key generation, validation, usage tracking, and rate limiting
 * for selling proxy access to multiple users.
 * 
 * Keys are stored as SHA-256 hashes for security.
 * The full key is only shown once at creation time.
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
            name TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            expires_at TEXT,
            max_requests_per_day INTEGER NOT NULL DEFAULT 100,
            max_requests_per_month INTEGER NOT NULL DEFAULT 3000,
            requests_today INTEGER NOT NULL DEFAULT 0,
            requests_this_month INTEGER NOT NULL DEFAULT 0,
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
            timestamp TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (key_id) REFERENCES api_keys(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
        CREATE INDEX IF NOT EXISTS idx_api_key_logs_key_id ON api_key_logs(key_id);
        CREATE INDEX IF NOT EXISTS idx_api_key_logs_timestamp ON api_key_logs(timestamp);
    `);

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
 * Check and reset daily/monthly counters if needed
 */
function resetCountersIfNeeded(keyRow) {
    const now = new Date();
    const today = now.toISOString().split('T')[0]; // YYYY-MM-DD
    const thisMonth = today.substring(0, 7); // YYYY-MM

    const database = initDB();
    let updated = false;

    if (keyRow.last_reset_day !== today) {
        database.prepare(`
            UPDATE api_keys SET requests_today = 0, last_reset_day = ? WHERE id = ?
        `).run(today, keyRow.id);
        keyRow.requests_today = 0;
        keyRow.last_reset_day = today;
        updated = true;
    }

    if (keyRow.last_reset_month !== thisMonth) {
        database.prepare(`
            UPDATE api_keys SET requests_this_month = 0, last_reset_month = ? WHERE id = ?
        `).run(thisMonth, keyRow.id);
        keyRow.requests_this_month = 0;
        keyRow.last_reset_month = thisMonth;
        updated = true;
    }

    return keyRow;
}

/**
 * Create a new API key
 * @param {Object} options
 * @param {string} options.name - Client/user name
 * @param {number} [options.maxRequestsPerDay=100] - Daily request limit
 * @param {number} [options.maxRequestsPerMonth=3000] - Monthly request limit
 * @param {string} [options.expiresAt] - Expiration date (ISO string)
 * @returns {Object} { id, key, keyPrefix, name, ... } - key is the full key (shown only once)
 */
export function createKey({ name, maxRequestsPerDay = 100, maxRequestsPerMonth = 3000, expiresAt = null }) {
    const database = initDB();

    if (!name || typeof name !== 'string' || name.trim().length === 0) {
        throw new Error('Name is required');
    }

    const key = generateKeyString();
    const keyHash = hashKey(key);
    const keyPrefix = key.substring(0, 11) + '...'; // "ag-xxxxxxxx..."

    const now = new Date();
    const today = now.toISOString().split('T')[0];
    const thisMonth = today.substring(0, 7);

    const stmt = database.prepare(`
        INSERT INTO api_keys (key_hash, key_prefix, name, max_requests_per_day, max_requests_per_month, expires_at, last_reset_day, last_reset_month)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const result = stmt.run(keyHash, keyPrefix, name.trim(), maxRequestsPerDay, maxRequestsPerMonth, expiresAt, today, thisMonth);

    logger.info(`[API Keys] Created key "${name}" (${keyPrefix}), ID: ${result.lastInsertRowid}`);

    return {
        id: result.lastInsertRowid,
        key, // Full key - shown only once!
        keyPrefix,
        name: name.trim(),
        enabled: true,
        maxRequestsPerDay,
        maxRequestsPerMonth,
        expiresAt,
        createdAt: now.toISOString()
    };
}

/**
 * Validate an API key and check limits
 * @param {string} key - The full API key
 * @returns {{ valid: boolean, keyInfo?: Object, error?: string }}
 */
export function validateKey(key) {
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

    // Check daily limit
    if (keyRow.requests_today >= keyRow.max_requests_per_day) {
        return { valid: false, error: `Daily request limit exceeded (${keyRow.max_requests_per_day}/day)` };
    }

    // Check monthly limit
    if (keyRow.requests_this_month >= keyRow.max_requests_per_month) {
        return { valid: false, error: `Monthly request limit exceeded (${keyRow.max_requests_per_month}/month)` };
    }

    return {
        valid: true,
        keyInfo: {
            id: keyRow.id,
            keyPrefix: keyRow.key_prefix,
            name: keyRow.name,
            requestsToday: keyRow.requests_today,
            requestsThisMonth: keyRow.requests_this_month,
            maxRequestsPerDay: keyRow.max_requests_per_day,
            maxRequestsPerMonth: keyRow.max_requests_per_month
        }
    };
}

/**
 * Increment usage counters for a key (called after successful request)
 * @param {number} keyId - Key ID
 * @param {Object} [logData] - Optional log data
 * @param {string} [logData.model] - Model used
 * @param {string} [logData.endpoint] - Endpoint called
 * @param {number} [logData.statusCode] - HTTP status code
 */
export function incrementUsage(keyId, logData = {}) {
    const database = initDB();

    database.prepare(`
        UPDATE api_keys 
        SET requests_today = requests_today + 1, 
            requests_this_month = requests_this_month + 1, 
            total_requests = total_requests + 1,
            last_used = datetime('now')
        WHERE id = ?
    `).run(keyId);

    // Log the request
    if (logData.model || logData.endpoint) {
        database.prepare(`
            INSERT INTO api_key_logs (key_id, model, endpoint, status_code)
            VALUES (?, ?, ?, ?)
        `).run(keyId, logData.model || null, logData.endpoint || null, logData.statusCode || null);
    }
}

/**
 * List all API keys (without hashes)
 * @returns {Array} List of keys with usage info
 */
export function listKeys() {
    const database = initDB();

    const keys = database.prepare(`
        SELECT id, key_prefix, name, enabled, created_at, expires_at,
               max_requests_per_day, max_requests_per_month,
               requests_today, requests_this_month, total_requests,
               last_used, last_reset_day, last_reset_month
        FROM api_keys
        ORDER BY created_at DESC
    `).all();

    // Reset counters for accurate display
    return keys.map(key => {
        const resetKey = resetCountersIfNeeded(key);
        return {
            id: resetKey.id,
            keyPrefix: resetKey.key_prefix,
            name: resetKey.name,
            enabled: !!resetKey.enabled,
            createdAt: resetKey.created_at,
            expiresAt: resetKey.expires_at,
            maxRequestsPerDay: resetKey.max_requests_per_day,
            maxRequestsPerMonth: resetKey.max_requests_per_month,
            requestsToday: resetKey.requests_today,
            requestsThisMonth: resetKey.requests_this_month,
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
    if (keyRow.requests_today >= keyRow.max_requests_per_day) return 'daily_limit';
    if (keyRow.requests_this_month >= keyRow.max_requests_per_month) return 'monthly_limit';
    return 'active';
}

/**
 * Revoke (disable) an API key
 * @param {number} id - Key ID
 */
export function revokeKey(id) {
    const database = initDB();
    const result = database.prepare('UPDATE api_keys SET enabled = 0 WHERE id = ?').run(id);
    if (result.changes === 0) throw new Error(`Key ID ${id} not found`);
    logger.info(`[API Keys] Key ID ${id} revoked`);
}

/**
 * Enable an API key
 * @param {number} id - Key ID
 */
export function enableKey(id) {
    const database = initDB();
    const result = database.prepare('UPDATE api_keys SET enabled = 1 WHERE id = ?').run(id);
    if (result.changes === 0) throw new Error(`Key ID ${id} not found`);
    logger.info(`[API Keys] Key ID ${id} enabled`);
}

/**
 * Delete an API key permanently
 * @param {number} id - Key ID
 */
export function deleteKey(id) {
    const database = initDB();
    const result = database.prepare('DELETE FROM api_keys WHERE id = ?').run(id);
    if (result.changes === 0) throw new Error(`Key ID ${id} not found`);
    logger.info(`[API Keys] Key ID ${id} deleted permanently`);
}

/**
 * Update key settings
 * @param {number} id - Key ID
 * @param {Object} updates
 */
export function updateKey(id, updates) {
    const database = initDB();

    const allowedFields = ['name', 'max_requests_per_day', 'max_requests_per_month', 'expires_at', 'enabled'];
    const setClauses = [];
    const values = [];

    // Map camelCase to snake_case
    const fieldMap = {
        name: 'name',
        maxRequestsPerDay: 'max_requests_per_day',
        maxRequestsPerMonth: 'max_requests_per_month',
        expiresAt: 'expires_at',
        enabled: 'enabled'
    };

    for (const [camelKey, snakeKey] of Object.entries(fieldMap)) {
        if (updates[camelKey] !== undefined) {
            if (!allowedFields.includes(snakeKey)) continue;
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
    logger.info(`[API Keys] Key ID ${id} updated: ${setClauses.join(', ')}`);
}

/**
 * Get usage statistics for a specific key
 * @param {number} id - Key ID
 * @param {number} [days=7] - Number of days to look back
 * @returns {Object} Usage stats
 */
export function getKeyUsage(id, days = 7) {
    const database = initDB();

    const key = database.prepare('SELECT * FROM api_keys WHERE id = ?').get(id);
    if (!key) throw new Error(`Key ID ${id} not found`);

    // Get request logs for the specified period
    const logs = database.prepare(`
        SELECT model, endpoint, status_code, timestamp
        FROM api_key_logs
        WHERE key_id = ? AND timestamp >= datetime('now', ?)
        ORDER BY timestamp DESC
        LIMIT 500
    `).all(id, `-${days} days`);

    // Aggregate by model
    const byModel = {};
    for (const log of logs) {
        const model = log.model || 'unknown';
        byModel[model] = (byModel[model] || 0) + 1;
    }

    // Aggregate by day
    const byDay = {};
    for (const log of logs) {
        const day = log.timestamp.split('T')[0].split(' ')[0];
        byDay[day] = (byDay[day] || 0) + 1;
    }

    return {
        keyId: id,
        keyPrefix: key.key_prefix,
        name: key.name,
        totalRequests: key.total_requests,
        requestsToday: key.requests_today,
        requestsThisMonth: key.requests_this_month,
        byModel,
        byDay,
        recentLogs: logs.slice(0, 50)
    };
}

/**
 * Check if multi-key mode is enabled
 * Returns true if there is at least one API key in the database
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
