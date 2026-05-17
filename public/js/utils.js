/**
 * Utility functions for Antigravity Console
 */

window.utils = {
    /**
     * Get the session token from localStorage
     * @returns {string|null} Session token
     */
    getSessionToken() {
        return localStorage.getItem('antigravity_session_token');
    },

    /**
     * Shared Request Wrapper — uses Bearer token authentication
     * Automatically redirects to login page on 401 responses.
     */
    async request(url, options = {}, webuiPassword = '') {
        options.headers = options.headers || {};

        // Attach session token as Bearer auth
        const token = this.getSessionToken();
        if (token) {
            options.headers['Authorization'] = 'Bearer ' + token;
        }

        // Legacy fallback: also send x-webui-password if available
        if (webuiPassword) {
            options.headers['x-webui-password'] = webuiPassword;
        }

        let response = await fetch(url, options);

        if (response.status === 401) {
            // Session expired or invalid — redirect to login
            localStorage.removeItem('antigravity_session_token');
            window.location.href = '/login.html';
            // Return a never-resolving promise to prevent further code execution
            return new Promise(() => {});
        }

        return { response, newPassword: null };
    },

    formatTimeUntil(isoTime) {
        const store = Alpine.store('global');
        const diff = new Date(isoTime) - new Date();
        if (diff <= 0) return store ? store.t('ready') : 'READY';
        const mins = Math.floor(diff / 60000);
        const hrs = Math.floor(mins / 60);

        const hSuffix = store ? store.t('timeH') : 'H';
        const mSuffix = store ? store.t('timeM') : 'M';

        if (hrs > 0) return `${hrs}${hSuffix} ${mins % 60}${mSuffix}`;
        return `${mins}${mSuffix}`;
    },

    getThemeColor(name) {
        return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    },

    /**
     * Debounce function - delays execution until after specified wait time
     * @param {Function} func - Function to debounce
     * @param {number} wait - Wait time in milliseconds
     * @returns {Function} Debounced function
     */
    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    },

    /**
     * Logout — clear session and redirect to login
     */
    logout() {
        const token = this.getSessionToken();
        if (token) {
            fetch('/api/auth/logout', {
                method: 'POST',
                headers: { 'Authorization': 'Bearer ' + token }
            }).catch(() => {});
        }
        localStorage.removeItem('antigravity_session_token');
        localStorage.removeItem('antigravity_webui_password');
        window.location.href = '/login.html';
    }
};
