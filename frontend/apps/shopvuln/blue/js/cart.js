/**
 * BLUE TEAM - SECURE Shopping Cart Handler for ShopVuln
 * 
 * SECURITY FIXES FROM RED TEAM:
 * ✓ Server-side price validation - prices are NEVER trusted from client
 * ✓ All price calculations done server-side
 * ✓ Cart manipulation requires server verification
 * ✓ Quantity validation (min/max limits)
 * ✓ CSRF protection on all cart modifications
 * ✓ XSS prevention using textContent
 * ✓ No client-side price/total manipulation possible
 * ✓ Session-based cart storage (server-side)
 * 
 * This file handles shopping cart operations with security best practices.
 * CRITICAL: All prices come from the server - client cannot manipulate pricing.
 */

const SecureCart = {
    cart: null,
    
    /**
     * Initialize cart page
     */
    async init() {
        await this.loadCart();
        this.setupEventListeners();
    },
    
    /**
     * Setup event listeners
     */
    setupEventListeners() {
        // Checkout button
        const checkoutBtn = document.getElementById('checkout-btn');
        if (checkoutBtn) {
            checkoutBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.proceedToCheckout();
            });
        }
        
        // Clear cart button
        const clearBtn = document.getElementById('clear-cart-btn');
        if (clearBtn) {
            clearBtn.addEventListener('click', async (e) => {
                e.preventDefault();
                if (confirm('Are you sure you want to clear your cart?')) {
                    await this.clearCart();
                }
            });
        }
        
        // Continue shopping button
        const continueBtn = document.getElementById('continue-shopping-btn');
        if (continueBtn) {
            continueBtn.addEventListener('click', (e) => {
                e.preventDefault();
                window.location.href = '/shopvuln/products';
            });
        }
    },
    
    /**
     * Load cart from server
     * SECURITY: All cart data comes from server, including prices
     */
    async loadCart() {
        try {
            const loadingEl = document.getElementById('cart-loading');
            if (loadingEl) loadingEl.style.display = 'block';
            
            const response = await SecureAPI.cart.get();
            
            if (loadingEl) loadingEl.style.display = 'none';
            
            if (response.success && response.data) {
                this.cart = response.data;
                this.renderCart();
            } else {
                this.showError('Failed to load cart');
            }
            
        } catch (error) {
            console.error('Error loading cart:', error);
            this.showError('Failed to load cart. Please try again.');
            
            const loadingEl = document.getElementById('cart-loading');
            if (loadingEl) loadingEl.style.display = 'none';
        }
    },
    
    /**
     * Render cart items
     */
    renderCart() {
        const container = document.getElementById('cart-items-container');
        const summaryContainer = document.getElementById('cart-summary');
        
        if (!container) return;
        
        container.innerHTML = '';
        
        // Check if cart is empty
        if (!this.cart || !this.cart.items || this.cart.items.length === 0) {
            const emptyMessage = document.createElement('div');
            emptyMessage.className = 'text-center p-5';
            
            const icon = document.createElement('i');
            icon.className = 'fas fa-shopping-cart fa-3x text-muted mb-3';
            emptyMessage.appendChild(icon);
            
            const message = SecureUtils.createElementWithText('p', 'Your cart is empty', 'lead');
            emptyMessage.appendChild(message);
            
            const shopBtn = document.createElement('a');
            shopBtn.href = '/shopvuln/products';
            shopBtn.className = 'btn btn-primary';
            shopBtn.textContent = 'Start Shopping';
            emptyMessage.appendChild(shopBtn);
            
            container.appendChild(emptyMessage);
            
            if (summaryContainer) {
                summaryContainer.style.display = 'none';
            }
            
            return;
        }
        
        // Render each cart item
        this.cart.items.forEach(item => {
            const itemElement = this.createCartItem(item);
            container.appendChild(itemElement);
        });
        
        // Render cart summary
        this.renderCartSummary();
        
        if (summaryContainer) {
            summaryContainer.style.display = 'block';
        }
    },
    
    /**
     * Create cart item element
     */
    createCartItem(item) {
        const row = document.createElement('div');
        row.className = 'cart-item row align-items-center mb-3 pb-3 border-bottom';
        row.dataset.itemId = item.id;
        
        // Product image
        const imgCol = document.createElement('div');
        imgCol.className = 'col-md-2 col-sm-3';
        
        const img = document.createElement('img');
        img.src = item.product?.image || '/static/images/placeholder.jpg';
        img.alt = SecureUtils.sanitizeInput(item.product?.name || 'Product', 100);
        img.className = 'img-fluid rounded';
        imgCol.appendChild(img);
        
        row.appendChild(imgCol);
        
        // Product details
        const detailsCol = document.createElement('div');
        detailsCol.className = 'col-md-4 col-sm-5';
        
        const name = document.createElement('h5');
        name.textContent = SecureUtils.sanitizeInput(item.product?.name || 'Unknown Product', 100);
        detailsCol.appendChild(name);
        
        // SECURITY: Display server-provided price only
        const price = document.createElement('p');
        price.className = 'text-muted mb-0';
        price.textContent = `Price: ${SecureUtils.formatPrice(item.price)}`;
        detailsCol.appendChild(price);
        
        row.appendChild(detailsCol);
        
        // Quantity controls
        const quantityCol = document.createElement('div');
        quantityCol.className = 'col-md-2 col-sm-4';
        
        const quantityGroup = document.createElement('div');
        quantityGroup.className = 'input-group';
        
        const decreaseBtn = document.createElement('button');
        decreaseBtn.className = 'btn btn-outline-secondary';
        decreaseBtn.type = 'button';
        decreaseBtn.textContent = '-';
        decreaseBtn.onclick = async () => {
            const newQty = Math.max(1, item.quantity - 1);
            await this.updateQuantity(item.id, newQty);
        };
        
        const quantityInput = document.createElement('input');
        quantityInput.type = 'number';
        quantityInput.className = 'form-control text-center';
        quantityInput.value = item.quantity;
        quantityInput.min = '1';
        quantityInput.max = '100';
        quantityInput.onchange = async (e) => {
            const newQty = parseInt(e.target.value, 10);
            if (SecureUtils.validateInteger(newQty, 1, 100)) {
                await this.updateQuantity(item.id, newQty);
            } else {
                e.target.value = item.quantity;
                SecureUtils.showError('Quantity must be between 1 and 100');
            }
        };
        
        const increaseBtn = document.createElement('button');
        increaseBtn.className = 'btn btn-outline-secondary';
        increaseBtn.type = 'button';
        increaseBtn.textContent = '+';
        increaseBtn.onclick = async () => {
            const newQty = Math.min(100, item.quantity + 1);
            await this.updateQuantity(item.id, newQty);
        };
        
        quantityGroup.appendChild(decreaseBtn);
        quantityGroup.appendChild(quantityInput);
        quantityGroup.appendChild(increaseBtn);
        quantityCol.appendChild(quantityGroup);
        
        row.appendChild(quantityCol);
        
        // Subtotal - SECURITY: Calculated server-side
        const subtotalCol = document.createElement('div');
        subtotalCol.className = 'col-md-2 col-sm-6';
        
        const subtotal = document.createElement('p');
        subtotal.className = 'h5 mb-0';
        subtotal.textContent = SecureUtils.formatPrice(item.subtotal || (item.price * item.quantity));
        subtotalCol.appendChild(subtotal);
        
        row.appendChild(subtotalCol);
        
        // Remove button
        const removeCol = document.createElement('div');
        removeCol.className = 'col-md-2 col-sm-6 text-end';
        
        const removeBtn = document.createElement('button');
        removeBtn.className = 'btn btn-danger btn-sm';
        removeBtn.innerHTML = '<i class="fas fa-trash"></i> Remove';
        removeBtn.onclick = async () => {
            if (confirm('Remove this item from cart?')) {
                await this.removeItem(item.id);
            }
        };
        removeCol.appendChild(removeBtn);
        
        row.appendChild(removeCol);
        
        return row;
    },
    
    /**
     * Render cart summary
     * SECURITY: All totals come from server
     */
    renderCartSummary() {
        const summaryBody = document.getElementById('cart-summary-body');
        const totalEl = document.getElementById('cart-total');
        
        if (!summaryBody || !this.cart) return;
        
        summaryBody.innerHTML = '';
        
        // Subtotal
        const subtotalRow = document.createElement('div');
        subtotalRow.className = 'd-flex justify-content-between mb-2';
        subtotalRow.appendChild(SecureUtils.createElementWithText('span', 'Subtotal:'));
        subtotalRow.appendChild(SecureUtils.createElementWithText('span', SecureUtils.formatPrice(this.cart.subtotal || 0)));
        summaryBody.appendChild(subtotalRow);
        
        // Discount (if any)
        if (this.cart.discount && this.cart.discount > 0) {
            const discountRow = document.createElement('div');
            discountRow.className = 'd-flex justify-content-between mb-2 text-success';
            discountRow.appendChild(SecureUtils.createElementWithText('span', 'Discount:'));
            discountRow.appendChild(SecureUtils.createElementWithText('span', `-${SecureUtils.formatPrice(this.cart.discount)}`));
            summaryBody.appendChild(discountRow);
            
            // Show applied coupon
            if (this.cart.coupon_code) {
                const couponRow = document.createElement('div');
                couponRow.className = 'd-flex justify-content-between mb-2 text-muted small';
                couponRow.appendChild(SecureUtils.createElementWithText('span', 'Coupon:'));
                couponRow.appendChild(SecureUtils.createElementWithText('span', this.cart.coupon_code));
                summaryBody.appendChild(couponRow);
            }
        }
        
        // Tax (if applicable)
        if (this.cart.tax && this.cart.tax > 0) {
            const taxRow = document.createElement('div');
            taxRow.className = 'd-flex justify-content-between mb-2';
            taxRow.appendChild(SecureUtils.createElementWithText('span', 'Tax:'));
            taxRow.appendChild(SecureUtils.createElementWithText('span', SecureUtils.formatPrice(this.cart.tax)));
            summaryBody.appendChild(taxRow);
        }
        
        // Total - SECURITY: Server-calculated only
        if (totalEl) {
            totalEl.textContent = SecureUtils.formatPrice(this.cart.total || 0);
        }
    },
    
    /**
     * Update item quantity
     * SECURITY: Server validates and recalculates prices
     */
    async updateQuantity(itemId, quantity) {
        try {
            // Validate quantity client-side
            if (!SecureUtils.validateInteger(quantity, 1, 100)) {
                SecureUtils.showError('Invalid quantity');
                return;
            }
            
            const response = await SecureAPI.cart.update(itemId, quantity);
            
            if (response.success) {
                // Reload cart to get updated prices from server
                await this.loadCart();
            } else {
                SecureUtils.showError(response.message || 'Failed to update quantity');
            }
            
        } catch (error) {
            console.error('Error updating quantity:', error);
            SecureUtils.showError('Failed to update quantity. Please try again.');
        }
    },
    
    /**
     * Remove item from cart
     */
    async removeItem(itemId) {
        try {
            const response = await SecureAPI.cart.remove(itemId);
            
            if (response.success) {
                await this.loadCart();
                SecureUtils.showSuccess('Item removed from cart');
            } else {
                SecureUtils.showError(response.message || 'Failed to remove item');
            }
            
        } catch (error) {
            console.error('Error removing item:', error);
            SecureUtils.showError('Failed to remove item. Please try again.');
        }
    },
    
    /**
     * Clear entire cart
     */
    async clearCart() {
        try {
            const response = await SecureAPI.cart.clear();
            
            if (response.success) {
                await this.loadCart();
                SecureUtils.showSuccess('Cart cleared');
            } else {
                SecureUtils.showError(response.message || 'Failed to clear cart');
            }
            
        } catch (error) {
            console.error('Error clearing cart:', error);
            SecureUtils.showError('Failed to clear cart. Please try again.');
        }
    },
    
    /**
     * Proceed to checkout
     */
    proceedToCheckout() {
        if (!this.cart || !this.cart.items || this.cart.items.length === 0) {
            SecureUtils.showError('Your cart is empty');
            return;
        }
        
        window.location.href = '/shopvuln/checkout';
    },
    
    /**
     * Show error message
     */
    showError(message) {
        SecureUtils.showError(message, 'cart-error');
    }
};

// Initialize on page load
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => SecureCart.init());
} else {
    SecureCart.init();
}
