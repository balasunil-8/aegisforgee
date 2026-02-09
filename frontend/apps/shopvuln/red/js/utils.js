/**
 * ⚠️ VULNERABLE CODE - FOR EDUCATIONAL PURPOSES ONLY ⚠️
 * 
 * ShopVuln Red Team - Utility Functions (VULNERABLE VERSION)
 * 
 * This file contains intentionally vulnerable code for security training.
 * DO NOT use this code in production environments.
 * 
 * Vulnerabilities:
 * - NO input sanitization (intentional for XSS)
 * - NO output encoding
 * - Dangerous innerHTML usage
 * - Client-side price calculations (manipulation possible)
 * - No data validation
 */

/**
 * VULNERABILITY: No sanitization - allows XSS attacks
 * This function intentionally does NOT sanitize HTML
 */
export function renderHTML(elementId, htmlContent) {
    const element = document.getElementById(elementId);
    if (element) {
        // DANGEROUS: Using innerHTML without sanitization
        element.innerHTML = htmlContent;
    }
}

/**
 * VULNERABILITY: No encoding - allows script injection
 */
export function displayMessage(message, type = 'info') {
    const messageDiv = document.createElement('div');
    messageDiv.className = `alert alert-${type}`;
    
    // DANGEROUS: Direct innerHTML usage with user input
    messageDiv.innerHTML = message;
    
    const container = document.getElementById('messages') || document.body;
    container.appendChild(messageDiv);
    
    setTimeout(() => messageDiv.remove(), 5000);
}

/**
 * VULNERABILITY: Client-side price calculation can be manipulated
 */
export function calculateTotal(items) {
    // VULNERABLE: Trusts client-side price data
    return items.reduce((total, item) => {
        return total + (parseFloat(item.price) * parseInt(item.quantity));
    }, 0);
}

/**
 * VULNERABILITY: No validation of discount amount
 */
export function applyDiscount(price, discountPercent) {
    // VULNERABLE: No bounds checking on discount
    return price - (price * (discountPercent / 100));
}

/**
 * VULNERABILITY: Formats currency but doesn't validate the amount
 */
export function formatCurrency(amount) {
    // VULNERABLE: No validation that amount is legitimate
    return `$${parseFloat(amount).toFixed(2)}`;
}

/**
 * VULNERABILITY: No URL validation - can load external resources
 */
export function loadImage(url, altText) {
    // VULNERABLE: No URL validation, could load malicious content
    return `<img src="${url}" alt="${altText}" onerror="this.src='/images/placeholder.png'">`;
}

/**
 * VULNERABILITY: Creates elements from user input without sanitization
 */
export function createProductCard(product) {
    // VULNERABLE: User input directly in template
    return `
        <div class="product-card" data-id="${product.id}">
            <div class="product-image">
                ${loadImage(product.image, product.name)}
            </div>
            <h3 class="product-name">${product.name}</h3>
            <p class="product-description">${product.description}</p>
            <div class="product-price">${formatCurrency(product.price)}</div>
            <button class="btn-add-cart" data-id="${product.id}" data-price="${product.price}">
                Add to Cart
            </button>
        </div>
    `;
}

/**
 * VULNERABILITY: No validation of review content
 */
export function createReviewCard(review) {
    // VULNERABLE: Direct injection of user content
    return `
        <div class="review-card">
            <div class="review-header">
                <span class="review-author">${review.author}</span>
                <span class="review-rating">${'⭐'.repeat(review.rating)}</span>
            </div>
            <div class="review-content">
                ${review.content}
            </div>
            <div class="review-date">${review.date}</div>
        </div>
    `;
}

/**
 * VULNERABILITY: localStorage used without encryption
 */
export function saveToStorage(key, data) {
    // VULNERABLE: Sensitive data stored in plain text
    localStorage.setItem(key, JSON.stringify(data));
}

export function getFromStorage(key) {
    const data = localStorage.getItem(key);
    return data ? JSON.parse(data) : null;
}

export function removeFromStorage(key) {
    localStorage.removeItem(key);
}

/**
 * VULNERABILITY: No session validation
 */
export function getUserSession() {
    // VULNERABLE: No verification of session validity
    return getFromStorage('userSession');
}

export function setUserSession(sessionData) {
    // VULNERABLE: Session data not encrypted
    saveToStorage('userSession', sessionData);
}

/**
 * VULNERABILITY: Query string built without encoding
 */
export function buildQueryString(params) {
    // VULNERABLE: No URL encoding, allows injection
    return Object.keys(params)
        .map(key => `${key}=${params[key]}`)
        .join('&');
}

/**
 * VULNERABILITY: Parses URL params without validation
 */
export function getUrlParams() {
    const params = {};
    const queryString = window.location.search.substring(1);
    const pairs = queryString.split('&');
    
    pairs.forEach(pair => {
        const [key, value] = pair.split('=');
        if (key) {
            // VULNERABLE: No decoding or validation
            params[key] = value;
        }
    });
    
    return params;
}

/**
 * VULNERABILITY: Evaluates user input as code
 */
export function executeCallback(callbackString) {
    // EXTREMELY DANGEROUS: eval() with user input
    if (callbackString) {
        eval(callbackString);
    }
}

/**
 * VULNERABILITY: No CSRF token
 */
export function getCSRFToken() {
    // VULNERABLE: Returns nothing - no CSRF protection
    return null;
}

/**
 * VULNERABILITY: Weak random number generation
 */
export function generateOrderId() {
    // VULNERABLE: Predictable order IDs
    return Math.floor(Math.random() * 1000000);
}

/**
 * VULNERABILITY: No rate limiting check
 */
export function checkRateLimit() {
    // VULNERABLE: Always returns true - no rate limiting
    return true;
}

export default {
    renderHTML,
    displayMessage,
    calculateTotal,
    applyDiscount,
    formatCurrency,
    loadImage,
    createProductCard,
    createReviewCard,
    saveToStorage,
    getFromStorage,
    removeFromStorage,
    getUserSession,
    setUserSession,
    buildQueryString,
    getUrlParams,
    executeCallback,
    getCSRFToken,
    generateOrderId,
    checkRateLimit
};
