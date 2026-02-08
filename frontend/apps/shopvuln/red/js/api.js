/**
 * ⚠️ VULNERABLE CODE - FOR EDUCATIONAL PURPOSES ONLY ⚠️
 * 
 * ShopVuln Red Team - API Configuration (VULNERABLE VERSION)
 * 
 * This file contains intentionally vulnerable code for security training.
 * DO NOT use this code in production environments.
 * 
 * Vulnerabilities:
 * - No request validation
 * - No CSRF protection
 * - No rate limiting on client side
 * - Credentials sent in plain text
 * - No request signing
 */

const API_BASE_URL = '/api/red/shopvuln';

class API {
    constructor() {
        this.baseURL = API_BASE_URL;
    }

    /**
     * VULNERABILITY: No authentication token validation
     * VULNERABILITY: No request encryption
     */
    async request(endpoint, options = {}) {
        const url = `${this.baseURL}${endpoint}`;
        
        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json',
            },
        };

        const config = { ...defaultOptions, ...options };

        try {
            const response = await fetch(url, config);
            
            // VULNERABILITY: No response validation
            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.message || 'API request failed');
            }

            return await response.json();
        } catch (error) {
            console.error('API Error:', error);
            throw error;
        }
    }

    async get(endpoint) {
        return this.request(endpoint, { method: 'GET' });
    }

    /**
     * VULNERABILITY: POST data not validated or sanitized
     */
    async post(endpoint, data) {
        return this.request(endpoint, {
            method: 'POST',
            body: JSON.stringify(data),
        });
    }

    async put(endpoint, data) {
        return this.request(endpoint, {
            method: 'PUT',
            body: JSON.stringify(data),
        });
    }

    async delete(endpoint) {
        return this.request(endpoint, { method: 'DELETE' });
    }
}

// Export singleton instance
const api = new API();
export default api;
