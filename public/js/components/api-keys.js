/**
 * API Keys Component - Manages API keys for multi-user access
 */
window.Components = window.Components || {};

window.Components.apiKeys = () => ({
    keys: [],
    summary: {},
    loading: false,
    showCreateModal: false,
    createdKey: null, // Full key shown only once after creation

    // Create/Edit form
    newKey: {
        id: null,
        name: '',
        notes: '',
        maxRequestsPerWindow: 120,
        windowHours: 3,
        maxRequestsPerDay: 0,
        maxRequestsPerMonth: 0,
        maxRpm: 0,
        maxDevices: 1,
        expiresAt: '',
        webhookUrl: ''
    },
    isEditing: false,

    // Viewing full key
    viewingKeyId: null,
    viewingKeyFull: '',

    // Usage modal
    showUsageModal: false,
    usageData: null,
    usageKeyName: '',

    init() {
        this.fetchKeys();
    },

    async fetchKeys() {
        this.loading = true;
        try {
            const password = Alpine.store('global').webuiPassword;
            const { response } = await window.utils.request('/api/keys', {}, password);
            const data = await response.json();
            if (data.status === 'ok') {
                this.keys = data.keys || [];
                this.summary = data.summary || {};
            }
        } catch (e) {
            console.error('Failed to fetch keys:', e);
        } finally {
            this.loading = false;
        }
    },

    openCreateModal() {
        this.isEditing = false;
        this.newKey = {
            id: null,
            name: '',
            notes: '',
            maxRequestsPerWindow: 120,
            windowHours: 3,
            maxRequestsPerDay: 0,
            maxRequestsPerMonth: 0,
            maxRpm: 0,
            maxDevices: 1,
            expiresAt: '',
            webhookUrl: ''
        };
        this.showCreateModal = true;
    },

    openEditModal(key) {
        this.isEditing = true;
        this.newKey = {
            id: key.id,
            name: key.name,
            notes: key.notes || '',
            maxRequestsPerWindow: key.maxRequestsPerWindow || 0,
            windowHours: key.windowHours || 0,
            maxRequestsPerDay: key.maxRequestsPerDay || 0,
            maxRequestsPerMonth: key.maxRequestsPerMonth || 0,
            maxRpm: key.maxRpm || 0,
            maxDevices: key.maxDevices || 1,
            expiresAt: key.expiresAt ? key.expiresAt.split('T')[0] : '',
            webhookUrl: key.webhookUrl || ''
        };
        this.showCreateModal = true;
    },

    async saveKey() {
        if (!this.newKey.name.trim()) {
            Alpine.store('global').showToast('Name is required', 'error');
            return;
        }
        try {
            const password = Alpine.store('global').webuiPassword;
            const url = this.isEditing ? `/api/keys/${this.newKey.id}` : '/api/keys';
            const method = this.isEditing ? 'PATCH' : 'POST';
            
            const bodyPayload = {
                name: this.newKey.name,
                notes: this.newKey.notes,
                maxRequestsPerWindow: parseInt(this.newKey.maxRequestsPerWindow) || 0,
                windowHours: parseInt(this.newKey.windowHours) || 0,
                maxRequestsPerDay: parseInt(this.newKey.maxRequestsPerDay) || 0,
                maxRequestsPerMonth: parseInt(this.newKey.maxRequestsPerMonth) || 0,
                maxRpm: parseInt(this.newKey.maxRpm) || 0,
                maxDevices: parseInt(this.newKey.maxDevices) || 1,
                expiresAt: this.newKey.expiresAt || null,
                webhookUrl: this.newKey.webhookUrl
            };

            const { response } = await window.utils.request(url, {
                method: method,
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(bodyPayload)
            }, password);
            const data = await response.json();
            if (data.status === 'ok') {
                if (!this.isEditing) {
                    this.createdKey = data.key; // Show full key once on creation
                }
                this.showCreateModal = false;
                Alpine.store('global').showToast(`Key "${this.newKey.name}" ${this.isEditing ? 'updated' : 'created'}!`, 'success');
                this.fetchKeys();
            } else {
                Alpine.store('global').showToast(data.error || 'Failed to save key', 'error');
            }
        } catch (e) {
            Alpine.store('global').showToast('Error: ' + e.message, 'error');
        }
    },

    async revokeKey(id) {
        if (!confirm('Are you sure you want to revoke this key?')) return;
        try {
            const password = Alpine.store('global').webuiPassword;
            await window.utils.request(`/api/keys/${id}/revoke`, { method: 'POST' }, password);
            Alpine.store('global').showToast('Key revoked', 'success');
            this.fetchKeys();
        } catch (e) {
            Alpine.store('global').showToast('Error: ' + e.message, 'error');
        }
    },

    async enableKeyAction(id) {
        try {
            const password = Alpine.store('global').webuiPassword;
            await window.utils.request(`/api/keys/${id}/enable`, { method: 'POST' }, password);
            Alpine.store('global').showToast('Key enabled', 'success');
            this.fetchKeys();
        } catch (e) {
            Alpine.store('global').showToast('Error: ' + e.message, 'error');
        }
    },

    async resetDevices(id) {
        if (!confirm('Reset all connected devices for this key?')) return;
        try {
            const password = Alpine.store('global').webuiPassword;
            await window.utils.request(`/api/keys/${id}/reset-devices`, { method: 'POST' }, password);
            Alpine.store('global').showToast('Devices reset successfully', 'success');
            this.fetchKeys();
        } catch (e) {
            Alpine.store('global').showToast('Error: ' + e.message, 'error');
        }
    },

    async deleteKeyAction(id) {
        if (!confirm('Permanently delete this key? This cannot be undone.')) return;
        try {
            const password = Alpine.store('global').webuiPassword;
            await window.utils.request(`/api/keys/${id}`, { method: 'DELETE' }, password);
            Alpine.store('global').showToast('Key deleted', 'success');
            this.fetchKeys();
        } catch (e) {
            Alpine.store('global').showToast('Error: ' + e.message, 'error');
        }
    },

    async viewUsage(id, name) {
        try {
            this.usageKeyName = name;
            const password = Alpine.store('global').webuiPassword;
            const { response } = await window.utils.request(`/api/keys/${id}/usage?days=7`, {}, password);
            const data = await response.json();
            if (data.status === 'ok') {
                this.usageData = data;
                this.showUsageModal = true;
            }
        } catch (e) {
            Alpine.store('global').showToast('Error: ' + e.message, 'error');
        }
    },

    copyKey() {
        if (this.createdKey) {
            navigator.clipboard.writeText(this.createdKey);
            Alpine.store('global').showToast('Key copied to clipboard!', 'success');
        }
    },

    copySpecificKey(fullKey) {
        if (fullKey) {
            navigator.clipboard.writeText(fullKey);
            Alpine.store('global').showToast('Key copied!', 'success');
        }
    },

    toggleKeyVisibility(key) {
        if (this.viewingKeyId === key.id) {
            this.viewingKeyId = null;
            this.viewingKeyFull = '';
        } else {
            this.viewingKeyId = key.id;
            this.viewingKeyFull = key.keyFull;
        }
    },

    getStatusBadge(status) {
        const badges = {
            active: 'badge-success',
            disabled: 'badge-error',
            expired: 'badge-warning',
            window_limit: 'badge-warning',
            daily_limit: 'badge-warning',
            monthly_limit: 'badge-warning'
        };
        return badges[status] || 'badge-ghost';
    },

    getStatusLabel(status) {
        const labels = {
            active: 'Active',
            disabled: 'Disabled',
            expired: 'Expired',
            window_limit: 'Window Limit',
            daily_limit: 'Daily Limit',
            monthly_limit: 'Monthly Limit'
        };
        return labels[status] || status;
    },

    formatDate(dateStr) {
        if (!dateStr) return '-';
        return new Date(dateStr).toLocaleDateString('en-US', {
            year: 'numeric', month: 'short', day: 'numeric'
        });
    },

    formatDateTime(dateStr) {
        if (!dateStr) return '-';
        return new Date(dateStr).toLocaleString('en-US', {
            month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
        });
    }
});
