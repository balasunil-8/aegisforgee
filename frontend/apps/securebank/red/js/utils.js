/**
 * SecureBank Utility Functions
 * Common helper functions used across the application
 */

// API Configuration
const API_CONFIG = {
    RED_TEAM_BASE_URL: 'http://localhost:5000/api/red/securebank',
    BLUE_TEAM_BASE_URL: 'http://localhost:5001/api/blue/securebank',
    TIMEOUT: 10000 // 10 seconds
};

// Determine which team version we're using based on current path
function getTeamMode() {
    const path = window.location.pathname;
    return path.includes('/blue/') ? 'blue' : 'red';
}

// Get appropriate API base URL
function getApiBaseUrl() {
    const team = getTeamMode();
    return team === 'blue' ? API_CONFIG.BLUE_TEAM_BASE_URL : API_CONFIG.RED_TEAM_BASE_URL;
}

/**
 * Make API request with common error handling
 * @param {string} endpoint - API endpoint (e.g., '/login')
 * @param {object} options - Fetch options
 * @returns {Promise<object>} - Response data
 */
async function apiRequest(endpoint, options = {}) {
    const baseUrl = getApiBaseUrl();
    const url = `${baseUrl}${endpoint}`;
    
    // Default options
    const defaultOptions = {
        credentials: 'include', // Include cookies for sessions
        headers: {
            'Content-Type': 'application/json'
        }
    };
    
    // Merge options
    const requestOptions = { ...defaultOptions, ...options };
    
    // Add CSRF token for Blue Team
    const team = getTeamMode();
    if (team === 'blue' && options.method && options.method !== 'GET') {
        const csrfToken = getCSRFToken();
        if (csrfToken) {
            requestOptions.headers['X-CSRF-Token'] = csrfToken;
        }
    }
    
    try {
        const response = await fetch(url, requestOptions);
        const data = await response.json();
        
        // Update CSRF token if provided in response (Blue Team)
        if (data.csrf_token || data.new_csrf_token) {
            setCSRFToken(data.csrf_token || data.new_csrf_token);
        }
        
        if (!response.ok) {
            throw new Error(data.error || `HTTP error! status: ${response.status}`);
        }
        
        return data;
    } catch (error) {
        console.error('API Request Error:', error);
        throw error;
    }
}

/**
 * Display alert message
 * @param {string} message - Message to display
 * @param {string} type - Alert type ('success', 'error', 'warning', 'info')
 */
function showAlert(message, type = 'info') {
    const container = document.getElementById('alert-container');
    if (!container) return;
    
    const alert = document.createElement('div');
    alert.className = `alert alert-${type}`;
    alert.innerHTML = `
        ${message}
        <span class="alert-close" onclick="this.parentElement.remove()">×</span>
    `;
    
    container.appendChild(alert);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (alert.parentElement) {
            alert.remove();
        }
    }, 5000);
}

/**
 * Show loading overlay
 */
function showLoading() {
    const overlay = document.getElementById('loading-overlay');
    if (overlay) {
        overlay.style.display = 'flex';
    }
}

/**
 * Hide loading overlay
 */
function hideLoading() {
    const overlay = document.getElementById('loading-overlay');
    if (overlay) {
        overlay.style.display = 'none';
    }
}

/**
 * Format currency
 * @param {number} amount - Amount to format
 * @param {string} currency - Currency code (default: USD)
 * @returns {string} - Formatted currency string
 */
function formatCurrency(amount, currency = 'USD') {
    return new Intl.NumberFormat('en-US', {
        style: 'currency',
        currency: currency
    }).format(amount);
}

/**
 * Format date
 * @param {string} dateString - ISO date string
 * @param {object} options - Intl.DateTimeFormat options
 * @returns {string} - Formatted date string
 */
function formatDate(dateString, options = {}) {
    if (!dateString) return 'N/A';
    
    const defaultOptions = {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
    };
    
    const date = new Date(dateString);
    return new Intl.DateTimeFormat('en-US', { ...defaultOptions, ...options }).format(date);
}

/**
 * Format date with time
 * @param {string} dateString - ISO date string
 * @returns {string} - Formatted date and time string
 */
function formatDateTime(dateString) {
    if (!dateString) return 'N/A';
    
    const date = new Date(dateString);
    return new Intl.DateTimeFormat('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    }).format(date);
}

/**
 * Get relative time (e.g., "2 hours ago")
 * @param {string} dateString - ISO date string
 * @returns {string} - Relative time string
 */
function getRelativeTime(dateString) {
    if (!dateString) return 'N/A';
    
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMins / 60);
    const diffDays = Math.floor(diffHours / 24);
    
    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins} minute${diffMins > 1 ? 's' : ''} ago`;
    if (diffHours < 24) return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
    if (diffDays < 7) return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
    
    return formatDate(dateString);
}

/**
 * Validate email format
 * @param {string} email - Email to validate
 * @returns {boolean} - True if valid
 */
function validateEmail(email) {
    const pattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return pattern.test(email);
}

/**
 * Validate phone format
 * @param {string} phone - Phone to validate
 * @returns {boolean} - True if valid
 */
function validatePhone(phone) {
    const pattern = /^\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}$/;
    return pattern.test(phone);
}

/**
 * Sanitize HTML to prevent XSS (Client-side - not foolproof)
 * Note: This is for demonstration. Server-side validation is critical.
 * @param {string} html - HTML string to sanitize
 * @returns {string} - Sanitized HTML
 */
function sanitizeHTML(html) {
    const div = document.createElement('div');
    div.textContent = html;
    return div.innerHTML;
}

/**
 * Escape HTML entities
 * @param {string} text - Text to escape
 * @returns {string} - Escaped text
 */
function escapeHTML(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}

/**
 * Get session data from localStorage
 * @returns {object|null} - Session data or null
 */
function getSession() {
    const sessionData = localStorage.getItem('securebank_session');
    return sessionData ? JSON.parse(sessionData) : null;
}

/**
 * Save session data to localStorage
 * @param {object} data - Session data to save
 */
function setSession(data) {
    localStorage.setItem('securebank_session', JSON.stringify(data));
}

/**
 * Clear session data
 */
function clearSession() {
    localStorage.removeItem('securebank_session');
    localStorage.removeItem('securebank_csrf_token');
}

/**
 * Get CSRF token (Blue Team)
 * @returns {string|null} - CSRF token or null
 */
function getCSRFToken() {
    return localStorage.getItem('securebank_csrf_token');
}

/**
 * Set CSRF token (Blue Team)
 * @param {string} token - CSRF token to save
 */
function setCSRFToken(token) {
    if (token) {
        localStorage.setItem('securebank_csrf_token', token);
    }
}

/**
 * Check if user is authenticated
 * @returns {boolean} - True if authenticated
 */
function isAuthenticated() {
    const session = getSession();
    return !!(session && session.user);
}

/**
 * Get current user from session
 * @returns {object|null} - User object or null
 */
function getCurrentUser() {
    const session = getSession();
    return session ? session.user : null;
}

/**
 * Redirect if not authenticated
 * @param {string} loginUrl - URL to redirect to if not authenticated
 */
function requireAuth(loginUrl = 'login.html') {
    if (!isAuthenticated()) {
        window.location.href = loginUrl;
    }
}

/**
 * Redirect if authenticated (for login page)
 * @param {string} dashboardUrl - URL to redirect to if authenticated
 */
function redirectIfAuth(dashboardUrl = 'dashboard.html') {
    if (isAuthenticated()) {
        window.location.href = dashboardUrl;
    }
}

/**
 * Debounce function
 * @param {function} func - Function to debounce
 * @param {number} wait - Wait time in milliseconds
 * @returns {function} - Debounced function
 */
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

/**
 * Copy text to clipboard
 * @param {string} text - Text to copy
 * @returns {Promise<void>}
 */
async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        showAlert('Copied to clipboard!', 'success');
    } catch (err) {
        console.error('Failed to copy:', err);
        showAlert('Failed to copy to clipboard', 'error');
    }
}

/**
 * Download data as file
 * @param {string} data - Data to download
 * @param {string} filename - Filename
 * @param {string} type - MIME type
 */
function downloadFile(data, filename, type = 'text/plain') {
    const blob = new Blob([data], { type });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    window.URL.revokeObjectURL(url);
}

// Export functions for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        getTeamMode,
        getApiBaseUrl,
        apiRequest,
        showAlert,
        showLoading,
        hideLoading,
        formatCurrency,
        formatDate,
        formatDateTime,
        getRelativeTime,
        validateEmail,
        validatePhone,
        sanitizeHTML,
        escapeHTML,
        getSession,
        setSession,
        clearSession,
        getCSRFToken,
        setCSRFToken,
        isAuthenticated,
        getCurrentUser,
        requireAuth,
        redirectIfAuth,
        debounce,
        copyToClipboard,
        downloadFile
    };
}
