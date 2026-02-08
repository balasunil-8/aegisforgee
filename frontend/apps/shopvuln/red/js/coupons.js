/**
 * ⚠️ VULNERABLE CODE - FOR EDUCATIONAL PURPOSES ONLY ⚠️
 * 
 * ShopVuln Red Team - Coupon Management (VULNERABLE VERSION)
 * 
 * This file contains intentionally vulnerable code for security training.
 * DO NOT use this code in production environments.
 * 
 * Vulnerabilities:
 * - Coupon stacking (multiple coupons on same order)
 * - No validation of coupon limits
 * - Client-side discount calculation
 * - No expiration checking
 * - Percentage coupons can exceed 100%
 * - Reusable single-use coupons
 * - No per-user coupon limits
 */

import api from './api.js';
import { 
    displayMessage, 
    formatCurrency, 
    applyDiscount,
    saveToStorage,
    getFromStorage 
} from './utils.js';

class CouponManager {
    constructor() {
        this.appliedCoupons = [];
        this.availableCoupons = [];
        this.init();
    }

    init() {
        this.loadAppliedCoupons();
        this.loadAvailableCoupons();
        this.setupEventListeners();
    }

    setupEventListeners() {
        const applyBtn = document.getElementById('apply-coupon-btn');
        const couponInput = document.getElementById('coupon-code-input');

        if (applyBtn) {
            applyBtn.addEventListener('click', () => {
                this.applyCoupon();
            });
        }

        if (couponInput) {
            couponInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    this.applyCoupon();
                }
            });
        }
    }

    /**
     * VULNERABILITY: Applied coupons stored in localStorage
     * Can be manipulated to add unlimited coupons
     */
    loadAppliedCoupons() {
        // VULNERABLE: No validation of loaded coupons
        this.appliedCoupons = getFromStorage('applied_coupons') || [];
    }

    saveAppliedCoupons() {
        // VULNERABLE: Saves to localStorage where it can be modified
        saveToStorage('applied_coupons', this.appliedCoupons);
    }

    async loadAvailableCoupons() {
        try {
            const response = await api.get('/coupons/available');
            this.availableCoupons = response.coupons || [];
            this.renderAvailableCoupons();
        } catch (error) {
            console.error('Failed to load coupons:', error);
        }
    }

    /**
     * VULNERABILITY: Coupon stacking - no limit on number of coupons
     * Multiple coupons can be applied to the same order
     */
    async applyCoupon() {
        const input = document.getElementById('coupon-code-input');
        const couponCode = input.value.trim().toUpperCase();

        if (!couponCode) {
            displayMessage('Please enter a coupon code', 'error');
            return;
        }

        try {
            // VULNERABLE: No check if coupon already applied
            const response = await api.post('/coupons/validate', {
                code: couponCode
            });

            if (response.valid) {
                const coupon = response.coupon;

                // VULNERABILITY: No check for duplicate coupons
                // Same coupon can be applied multiple times!
                this.appliedCoupons.push({
                    code: coupon.code,
                    type: coupon.type, // 'percentage' or 'fixed'
                    value: coupon.value,
                    description: coupon.description,
                    appliedAt: new Date().toISOString()
                });

                this.saveAppliedCoupons();
                this.updateOrderTotal();
                this.renderAppliedCoupons();

                displayMessage(`Coupon ${couponCode} applied!`, 'success');
                input.value = '';
            } else {
                displayMessage('Invalid coupon code', 'error');
            }
        } catch (error) {
            displayMessage(`Failed to apply coupon: ${error.message}`, 'error');
        }
    }

    /**
     * VULNERABILITY: Client-side discount calculation
     * Total discount calculated without server verification
     */
    calculateTotalDiscount(subtotal) {
        let totalDiscount = 0;

        // VULNERABLE: Applies ALL coupons without limit
        this.appliedCoupons.forEach(coupon => {
            if (coupon.type === 'percentage') {
                // VULNERABLE: No max percentage check
                // Could exceed 100% if multiple percentage coupons stacked
                const discount = subtotal * (parseFloat(coupon.value) / 100);
                totalDiscount += discount;
                
                // Update subtotal for next coupon (stacking!)
                subtotal -= discount;
            } else if (coupon.type === 'fixed') {
                // VULNERABLE: Fixed amount applied even if exceeds subtotal
                totalDiscount += parseFloat(coupon.value);
                subtotal -= parseFloat(coupon.value);
            }
        });

        // VULNERABLE: Could result in negative total
        return totalDiscount;
    }

    /**
     * VULNERABILITY: No validation that final price is positive
     */
    updateOrderTotal() {
        const subtotalElement = document.getElementById('order-subtotal');
        const discountElement = document.getElementById('order-discount');
        const totalElement = document.getElementById('order-total');

        if (!subtotalElement) return;

        const subtotal = parseFloat(subtotalElement.textContent.replace('$', ''));
        const discount = this.calculateTotalDiscount(subtotal);
        
        // VULNERABLE: Final total can be negative!
        const finalTotal = subtotal - discount;

        if (discountElement) {
            discountElement.textContent = formatCurrency(discount);
        }

        if (totalElement) {
            // VULNERABLE: Shows potentially negative total
            totalElement.textContent = formatCurrency(finalTotal);
        }

        // Update hidden input for checkout
        const totalInput = document.getElementById('final-total');
        if (totalInput) {
            // VULNERABLE: Client-controlled total
            totalInput.value = finalTotal;
        }
    }

    renderAppliedCoupons() {
        const container = document.getElementById('applied-coupons-container');
        if (!container) return;

        if (this.appliedCoupons.length === 0) {
            container.innerHTML = '<p class="no-coupons">No coupons applied</p>';
            return;
        }

        // VULNERABLE: Shows all stacked coupons
        const html = this.appliedCoupons.map((coupon, index) => `
            <div class="applied-coupon">
                <div class="coupon-info">
                    <strong>${coupon.code}</strong>
                    <span>${coupon.description}</span>
                    <span class="coupon-value">
                        ${coupon.type === 'percentage' ? `${coupon.value}%` : formatCurrency(coupon.value)} OFF
                    </span>
                </div>
                <button class="btn-remove-coupon" onclick="window.couponManager.removeCoupon(${index})">
                    Remove
                </button>
            </div>
        `).join('');

        container.innerHTML = html;
    }

    /**
     * VULNERABILITY: Can remove and re-add coupons indefinitely
     */
    removeCoupon(index) {
        // VULNERABLE: No restrictions on removing/re-adding
        this.appliedCoupons.splice(index, 1);
        this.saveAppliedCoupons();
        this.updateOrderTotal();
        this.renderAppliedCoupons();
        
        displayMessage('Coupon removed', 'info');
    }

    /**
     * VULNERABILITY: Shows all available coupons including expired ones
     */
    renderAvailableCoupons() {
        const container = document.getElementById('available-coupons-container');
        if (!container) return;

        if (this.availableCoupons.length === 0) return;

        const html = this.availableCoupons.map(coupon => `
            <div class="available-coupon" onclick="window.couponManager.quickApply('${coupon.code}')">
                <div class="coupon-code">${coupon.code}</div>
                <div class="coupon-desc">${coupon.description}</div>
                <div class="coupon-value">
                    ${coupon.type === 'percentage' ? `${coupon.value}% OFF` : `${formatCurrency(coupon.value)} OFF`}
                </div>
                ${coupon.expiresAt ? `<div class="coupon-expiry">Expires: ${coupon.expiresAt}</div>` : ''}
            </div>
        `).join('');

        container.innerHTML = `
            <div class="coupons-list">
                <h4>Available Coupons</h4>
                ${html}
            </div>
        `;
    }

    /**
     * VULNERABILITY: Quick apply doesn't check if already applied
     */
    async quickApply(code) {
        const input = document.getElementById('coupon-code-input');
        if (input) {
            input.value = code;
            await this.applyCoupon();
        }
    }

    /**
     * VULNERABILITY: Can manually add any coupon
     */
    addManualCoupon(code, type, value, description) {
        // VULNERABLE: No validation of coupon authenticity
        this.appliedCoupons.push({
            code: code,
            type: type,
            value: value,
            description: description,
            manual: true // Flag as manually added
        });

        this.saveAppliedCoupons();
        this.updateOrderTotal();
        this.renderAppliedCoupons();

        displayMessage(`Manual coupon added: ${code}`, 'success');
    }

    /**
     * VULNERABILITY: Applies all available coupons at once
     */
    async applyAllCoupons() {
        console.log('⚠️ APPLYING ALL COUPONS - STACKING VULNERABILITY ⚠️');

        for (const coupon of this.availableCoupons) {
            // VULNERABLE: No limit on coupon stacking
            this.appliedCoupons.push({
                code: coupon.code,
                type: coupon.type,
                value: coupon.value,
                description: coupon.description
            });
        }

        this.saveAppliedCoupons();
        this.updateOrderTotal();
        this.renderAppliedCoupons();

        displayMessage(`Applied ${this.availableCoupons.length} coupons!`, 'success');
    }

    /**
     * VULNERABILITY: Duplicates a coupon multiple times
     */
    duplicateCoupon(code, times = 5) {
        const coupon = this.appliedCoupons.find(c => c.code === code);
        
        if (coupon) {
            // VULNERABLE: Duplicates the same coupon
            for (let i = 0; i < times; i++) {
                this.appliedCoupons.push({ ...coupon });
            }

            this.saveAppliedCoupons();
            this.updateOrderTotal();
            this.renderAppliedCoupons();

            displayMessage(`Coupon ${code} duplicated ${times} times`, 'success');
        }
    }

    /**
     * VULNERABILITY: Modifies coupon value after application
     */
    modifyCouponValue(index, newValue) {
        if (this.appliedCoupons[index]) {
            // VULNERABLE: Can change discount value after applying
            this.appliedCoupons[index].value = newValue;
            
            this.saveAppliedCoupons();
            this.updateOrderTotal();
            this.renderAppliedCoupons();

            displayMessage(`Coupon value modified to ${newValue}`, 'success');
        }
    }

    /**
     * VULNERABILITY: Clears all coupons without restriction
     */
    clearAllCoupons() {
        this.appliedCoupons = [];
        this.saveAppliedCoupons();
        this.updateOrderTotal();
        this.renderAppliedCoupons();
        
        displayMessage('All coupons cleared', 'info');
    }

    /**
     * VULNERABILITY: Exports coupons for manipulation
     */
    exportCoupons() {
        const data = JSON.stringify(this.appliedCoupons, null, 2);
        console.log('Applied Coupons Export:', data);
        return data;
    }

    /**
     * VULNERABILITY: Imports coupons without validation
     */
    importCoupons(data) {
        try {
            // VULNERABLE: No validation of imported data
            this.appliedCoupons = JSON.parse(data);
            this.saveAppliedCoupons();
            this.updateOrderTotal();
            this.renderAppliedCoupons();
            
            displayMessage('Coupons imported successfully', 'success');
        } catch (error) {
            displayMessage('Invalid coupon data', 'error');
        }
    }

    /**
     * VULNERABILITY: Creates a custom coupon client-side
     */
    createCustomCoupon(code, type, value) {
        // EXTREMELY VULNERABLE: Allows creation of arbitrary coupons
        const customCoupon = {
            code: code || 'CUSTOM100',
            type: type || 'percentage',
            value: value || 100, // Default 100% off!
            description: 'Custom coupon created client-side',
            custom: true
        };

        this.appliedCoupons.push(customCoupon);
        this.saveAppliedCoupons();
        this.updateOrderTotal();
        this.renderAppliedCoupons();

        displayMessage(`Custom coupon created: ${customCoupon.code}`, 'success');
    }

    /**
     * VULNERABILITY: Submits order with stacked coupons
     */
    async submitOrderWithCoupons(orderData) {
        try {
            // VULNERABLE: Sends all stacked coupons to server
            const response = await api.post('/orders/create', {
                ...orderData,
                coupons: this.appliedCoupons, // Multiple coupons!
                discount: this.calculateTotalDiscount(orderData.subtotal),
                // Client calculates final total
                total: orderData.subtotal - this.calculateTotalDiscount(orderData.subtotal)
            });

            if (response.success) {
                displayMessage('Order placed with discounts!', 'success');
                this.clearAllCoupons();
                return response;
            }
        } catch (error) {
            displayMessage(`Order failed: ${error.message}`, 'error');
            throw error;
        }
    }

    /**
     * VULNERABILITY: No rate limiting on coupon validation
     */
    async bruteforceCoupon(prefix, length = 4) {
        console.log('⚠️ ATTEMPTING COUPON BRUTEFORCE ⚠️');
        
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        const attempts = [];

        // VULNERABLE: No rate limiting allows brute force
        for (let i = 0; i < 100; i++) {
            let code = prefix;
            for (let j = 0; j < length; j++) {
                code += chars.charAt(Math.floor(Math.random() * chars.length));
            }

            try {
                const response = await api.post('/coupons/validate', { code });
                if (response.valid) {
                    attempts.push(code);
                    displayMessage(`Found valid coupon: ${code}`, 'success');
                }
            } catch (error) {
                // Continue trying
            }
        }

        return attempts;
    }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        window.couponManager = new CouponManager();
    });
} else {
    window.couponManager = new CouponManager();
}

export default CouponManager;
