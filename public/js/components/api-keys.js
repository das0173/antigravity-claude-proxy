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

    // Create form
    newKey: {
        name: '',
        maxRequestsPerDay: 100,
        maxRequestsPerMonth: 3000,
        expiresAt: ''
    },

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

    async createKey() {
        if (!this.newKey.name.trim()) {
            Alpine.store('global').showToast('Name is required', 'error');
            return;
        }
        try {
            const password = Alpine.store('global').webuiPassword;
            const { response } = await window.utils.request('/api/keys', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    name: this.newKey.name,
                    maxRequestsPerDay: parseInt(this.newKey.maxRequestsPerDay) || 100,
                    maxRequestsPerMonth: parseInt(this.newKey.maxRequestsPerMonth) || 3000,
                    expiresAt: this.newKey.expiresAt || null
                })
            }, password);
            const data = await response.json();
            if (data.status === 'ok') {
                this.createdKey = data.key; // Show full key once
                this.showCreateModal = false;
                this.newKey = { name: '', maxRequestsPerDay: 100, maxRequestsPerMonth: 3000, expiresAt: '' };
                Alpine.store('global').showToast(`Key "${data.name}" created!`, 'success');
                this.fetchKeys();
            } else {
                Alpine.store('global').showToast(data.error || 'Failed to create key', 'error');
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

    getStatusBadge(status) {
        const badges = {
            active: 'badge-success',
            disabled: 'badge-error',
            expired: 'badge-warning',
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
