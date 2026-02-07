/**
 * BLUE TEAM - SECURE Coupon Handler for ShopVuln
 * 
 * SECURITY FIXES FROM RED TEAM:
 * ✓ Server-side coupon validation only
 * ✓ No client-side coupon generation or manipulation
 * ✓ Prevention of coupon stacking abuse
 * ✓ Server-side usage tracking and limits
 * ✓ Expiration date validation server-side
 * ✓ CSRF protection on coupon application
 * ✓ Input sanitization on coupon codes
 * ✓ Rate limiting on validation attempts
 * ✓ No discount calculation client-side
 * 
 * This file handles coupon operations with server-side validation.
 * CRITICAL: All coupon validation and discount calculation is server-side.
 */

const SecureCoupons = {
    activeCoupon: null,
    validationAttempts: 0,
    maxAttempts: 5,
    attemptResetTime: 60000, // 1 minute
    
    /**
     * Initialize coupon handler
     */
    init() {
        this.setupEventListeners();
        this.loadActiveCoupon();
    },
    
    /**
     * Setup event listeners
     */
    setupEventListeners() {
        // Apply coupon button
        const applyBtn = document.getElementById('apply-coupon-btn');
        if (applyBtn) {
            applyBtn.addEventListener('click', async (e) => {
                e.preventDefault();
                await this.applyCoupon();
            });
        }
        
        // Remove coupon button
        const removeBtn = document.getElementById('remove-coupon-btn');
        if (removeBtn) {
            removeBtn.addEventListener('click', async (e) => {
                e.preventDefault();
                await this.removeCoupon();
            });
        }
        
        // Coupon input - format on input
        const couponInput = document.getElementById('coupon-code');
        if (couponInput) {
            couponInput.addEventListener('input', (e) => {
                // Convert to uppercase and remove invalid characters
                e.target.value = e.target.value.toUpperCase().replace(/[^A-Z0-9]/g, '');
            });
            
            // Apply on Enter key
            couponInput.addEventListener('keypress', async (e) => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    await this.applyCoupon();
                }
            });
        }
    },
    
    /**
     * Load active coupon from cart
     */
    async loadActiveCoupon() {
        try {
            const response = await SecureAPI.cart.get();
            
            if (response.success && response.data) {
                if (response.data.coupon_code) {
                    this.activeCoupon = {
                        code: response.data.coupon_code,
                        discount: response.data.discount || 0,
                        discount_type: response.data.discount_type || 'fixed'
                    };
                    this.displayActiveCoupon();
                }
            }
        } catch (error) {
            console.error('Error loading active coupon:', error);
        }
    },
    
    /**
     * Apply coupon code
     * SECURITY: Server validates coupon and calculates discount
     */
    async applyCoupon() {
        // Rate limiting check
        if (this.validationAttempts >= this.maxAttempts) {
            SecureUtils.showError('Too many attempts. Please try again later.');
            return;
        }
        
        const couponInput = document.getElementById('coupon-code');
        if (!couponInput) return;
        
        const code = couponInput.value.trim();
        
        // Validate input
        if (!code || code.length < 3 || code.length > 50) {
            SecureUtils.showError('Please enter a valid coupon code (3-50 characters)');
            return;
        }
        
        try {
            const applyBtn = document.getElementById('apply-coupon-btn');
            if (applyBtn) {
                applyBtn.disabled = true;
                applyBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Applying...';
            }
            
            // Increment attempt counter
            this.validationAttempts++;
            
            // Reset counter after timeout
            setTimeout(() => {
                this.validationAttempts = Math.max(0, this.validationAttempts - 1);
            }, this.attemptResetTime);
            
            // Sanitize code
            const sanitizedCode = SecureUtils.sanitizeInput(code, 50).toUpperCase();
            
            // First validate the coupon
            const validateResponse = await SecureAPI.coupons.validate(sanitizedCode);
            
            if (!validateResponse.success) {
                throw new Error(validateResponse.message || 'Invalid coupon code');
            }
            
            // Then apply it to the cart
            const applyResponse = await SecureAPI.coupons.apply(sanitizedCode);
            
            if (applyResponse.success) {
                this.activeCoupon = {
                    code: sanitizedCode,
                    discount: applyResponse.data.discount || 0,
                    discount_type: applyResponse.data.discount_type || 'fixed'
                };
                
                SecureUtils.showSuccess(`Coupon "${sanitizedCode}" applied successfully!`);
                
                // Clear input
                couponInput.value = '';
                
                // Display active coupon
                this.displayActiveCoupon();
                
                // Trigger cart update event
                this.triggerCartUpdate();
                
                // Reset attempts on success
                this.validationAttempts = 0;
            } else {
                throw new Error(applyResponse.message || 'Failed to apply coupon');
            }
            
            if (applyBtn) {
                applyBtn.disabled = false;
                applyBtn.textContent = 'Apply';
            }
            
        } catch (error) {
            console.error('Error applying coupon:', error);
            SecureUtils.showError(error.message || 'Failed to apply coupon. Please try again.');
            
            const applyBtn = document.getElementById('apply-coupon-btn');
            if (applyBtn) {
                applyBtn.disabled = false;
                applyBtn.textContent = 'Apply';
            }
        }
    },
    
    /**
     * Remove active coupon
     */
    async removeCoupon() {
        if (!this.activeCoupon) {
            return;
        }
        
        try {
            const removeBtn = document.getElementById('remove-coupon-btn');
            if (removeBtn) {
                removeBtn.disabled = true;
            }
            
            const response = await SecureAPI.coupons.remove();
            
            if (response.success) {
                this.activeCoupon = null;
                SecureUtils.showSuccess('Coupon removed');
                
                // Hide active coupon display
                this.hideActiveCoupon();
                
                // Trigger cart update event
                this.triggerCartUpdate();
            } else {
                SecureUtils.showError(response.message || 'Failed to remove coupon');
            }
            
            if (removeBtn) {
                removeBtn.disabled = false;
            }
            
        } catch (error) {
            console.error('Error removing coupon:', error);
            SecureUtils.showError('Failed to remove coupon. Please try again.');
            
            const removeBtn = document.getElementById('remove-coupon-btn');
            if (removeBtn) {
                removeBtn.disabled = false;
            }
        }
    },
    
    /**
     * Display active coupon
     */
    displayActiveCoupon() {
        const container = document.getElementById('active-coupon-display');
        if (!container) return;
        
        container.innerHTML = '';
        container.style.display = 'block';
        
        const card = document.createElement('div');
        card.className = 'alert alert-success d-flex justify-content-between align-items-center';
        
        const infoDiv = document.createElement('div');
        
        // Coupon code
        const codeEl = document.createElement('strong');
        codeEl.textContent = SecureUtils.sanitizeInput(this.activeCoupon.code, 50);
        infoDiv.appendChild(codeEl);
        
        // Discount info
        const discountEl = document.createElement('div');
        discountEl.className = 'small text-muted';
        discountEl.textContent = this.formatDiscount(this.activeCoupon.discount, this.activeCoupon.discount_type);
        infoDiv.appendChild(discountEl);
        
        card.appendChild(infoDiv);
        
        // Remove button
        const removeBtn = document.createElement('button');
        removeBtn.className = 'btn btn-sm btn-outline-danger';
        removeBtn.innerHTML = '<i class="fas fa-times"></i>';
        removeBtn.onclick = async () => await this.removeCoupon();
        card.appendChild(removeBtn);
        
        container.appendChild(card);
        
        // Hide coupon input
        const inputGroup = document.getElementById('coupon-input-group');
        if (inputGroup) {
            inputGroup.style.display = 'none';
        }
    },
    
    /**
     * Hide active coupon display
     */
    hideActiveCoupon() {
        const container = document.getElementById('active-coupon-display');
        if (container) {
            container.innerHTML = '';
            container.style.display = 'none';
        }
        
        // Show coupon input
        const inputGroup = document.getElementById('coupon-input-group');
        if (inputGroup) {
            inputGroup.style.display = 'block';
        }
    },
    
    /**
     * Format discount for display
     */
    formatDiscount(discount, discountType) {
        if (discountType === 'percentage') {
            return `Save ${Math.round(discount)}%`;
        } else {
            return `Save ${SecureUtils.formatPrice(discount)}`;
        }
    },
    
    /**
     * Trigger cart update event
     * This allows other components to refresh when coupon changes
     */
    triggerCartUpdate() {
        const event = new CustomEvent('cart-updated', {
            detail: { coupon: this.activeCoupon }
        });
        window.dispatchEvent(event);
        
        // Also reload cart if SecureCart is available
        if (typeof SecureCart !== 'undefined' && SecureCart.loadCart) {
            SecureCart.loadCart();
        }
    },
    
    /**
     * Validate coupon format (client-side pre-check)
     * Note: This is just for UX - real validation is server-side
     */
    validateCouponFormat(code) {
        if (typeof code !== 'string') return false;
        
        // Must be 3-50 characters, alphanumeric only
        const regex = /^[A-Z0-9]{3,50}$/;
        return regex.test(code);
    },
    
    /**
     * Show available coupons (if endpoint exists)
     */
    async showAvailableCoupons() {
        const container = document.getElementById('available-coupons');
        if (!container) return;
        
        try {
            // This would call an endpoint that lists available coupons
            // For security, this should only show public/promotional coupons
            // NOT all valid coupons (to prevent enumeration)
            const response = await SecureAPI.get('/coupons/public');
            
            if (response.success && response.data && response.data.length > 0) {
                container.innerHTML = '';
                
                const heading = SecureUtils.createElementWithText('h6', 'Available Offers:', 'mb-2');
                container.appendChild(heading);
                
                response.data.forEach(coupon => {
                    const couponBadge = document.createElement('span');
                    couponBadge.className = 'badge bg-primary me-2 mb-2 cursor-pointer';
                    couponBadge.textContent = SecureUtils.sanitizeInput(coupon.code, 20);
                    couponBadge.onclick = () => {
                        const input = document.getElementById('coupon-code');
                        if (input) {
                            input.value = coupon.code;
                        }
                    };
                    container.appendChild(couponBadge);
                });
            }
        } catch (error) {
            console.error('Error loading available coupons:', error);
        }
    }
};

// Initialize on page load
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => SecureCoupons.init());
} else {
    SecureCoupons.init();
}

// Listen for cart updates from other components
window.addEventListener('cart-updated', () => {
    SecureCoupons.loadActiveCoupon();
});
