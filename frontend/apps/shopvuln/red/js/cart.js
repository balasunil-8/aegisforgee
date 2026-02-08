/**
 * ⚠️ VULNERABLE CODE - FOR EDUCATIONAL PURPOSES ONLY ⚠️
 * 
 * ShopVuln Red Team - Shopping Cart Management (VULNERABLE VERSION)
 * 
 * This file contains intentionally vulnerable code for security training.
 * DO NOT use this code in production environments.
 * 
 * Vulnerabilities:
 * - Price manipulation (client-side pricing)
 * - No server-side validation of prices
 * - localStorage tampering possible
 * - Quantity manipulation
 * - Direct price modification in requests
 * - No integrity checks
 */

import api from './api.js';
import { 
    renderHTML, 
    displayMessage, 
    formatCurrency, 
    calculateTotal,
    saveToStorage,
    getFromStorage 
} from './utils.js';

class CartManager {
    constructor() {
        this.cart = this.loadCart();
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.renderCart();
        this.syncWithServer();
    }

    /**
     * VULNERABILITY: Cart data loaded from localStorage without validation
     * Prices and quantities can be manipulated in localStorage
     */
    loadCart() {
        const savedCart = getFromStorage('shopping_cart');
        
        // VULNERABLE: No validation of cart data integrity
        return savedCart || { items: [] };
    }

    /**
     * VULNERABILITY: Cart saved to localStorage - can be tampered with
     */
    saveCart() {
        // VULNERABLE: Prices stored client-side can be modified
        saveToStorage('shopping_cart', this.cart);
    }

    setupEventListeners() {
        const updateButtons = document.querySelectorAll('.btn-update-quantity');
        const removeButtons = document.querySelectorAll('.btn-remove-item');
        const checkoutButton = document.getElementById('btn-checkout');

        updateButtons.forEach(btn => {
            btn.addEventListener('click', (e) => {
                const itemId = e.target.dataset.id;
                const newQuantity = prompt('Enter new quantity:');
                if (newQuantity) {
                    this.updateQuantity(itemId, parseInt(newQuantity));
                }
            });
        });

        removeButtons.forEach(btn => {
            btn.addEventListener('click', (e) => {
                const itemId = e.target.dataset.id;
                this.removeItem(itemId);
            });
        });

        if (checkoutButton) {
            checkoutButton.addEventListener('click', () => {
                window.location.href = '/checkout.html';
            });
        }
    }

    /**
     * VULNERABILITY: Adds item with client-provided price
     * Price can be manipulated before calling this function
     */
    async addItem(productId, productName, price, quantity = 1) {
        // VULNERABLE: Accepts client-side price without validation
        const existingItem = this.cart.items.find(item => item.productId === productId);

        if (existingItem) {
            // VULNERABLE: Updates with potentially manipulated price
            existingItem.quantity += quantity;
            existingItem.price = price; // Client can set any price!
        } else {
            this.cart.items.push({
                productId,
                name: productName,
                price: price, // VULNERABLE: Client-controlled price
                quantity: quantity
            });
        }

        this.saveCart();
        this.renderCart();

        try {
            // VULNERABLE: Sends client-side price to server
            await api.post('/cart/add', {
                productId,
                price, // Price from client!
                quantity
            });

            displayMessage(`${productName} added to cart`, 'success');
        } catch (error) {
            displayMessage(`Failed to add item: ${error.message}`, 'error');
        }
    }

    /**
     * VULNERABILITY: No validation of quantity
     * Can set negative quantities or extremely large numbers
     */
    async updateQuantity(productId, newQuantity) {
        const item = this.cart.items.find(item => item.productId === productId);

        if (!item) {
            displayMessage('Item not found in cart', 'error');
            return;
        }

        // VULNERABLE: No bounds checking on quantity
        item.quantity = newQuantity; // Could be negative or huge!

        this.saveCart();
        this.renderCart();

        try {
            // VULNERABLE: Sends unvalidated quantity to server
            await api.put(`/cart/update/${productId}`, {
                quantity: newQuantity,
                price: item.price // Also sending client-side price
            });

            displayMessage('Cart updated', 'success');
        } catch (error) {
            displayMessage(`Failed to update cart: ${error.message}`, 'error');
        }
    }

    async removeItem(productId) {
        this.cart.items = this.cart.items.filter(item => item.productId !== productId);
        
        this.saveCart();
        this.renderCart();

        try {
            await api.delete(`/cart/remove/${productId}`);
            displayMessage('Item removed from cart', 'success');
        } catch (error) {
            displayMessage(`Failed to remove item: ${error.message}`, 'error');
        }
    }

    /**
     * VULNERABILITY: Client-side price calculation
     * Total calculated from potentially manipulated prices
     */
    calculateCartTotal() {
        // VULNERABLE: Calculating total from client-side data
        return calculateTotal(this.cart.items);
    }

    /**
     * VULNERABILITY: Renders cart with unsanitized data
     */
    renderCart() {
        const container = document.getElementById('cart-container');
        if (!container) return;

        if (this.cart.items.length === 0) {
            container.innerHTML = '<p class="empty-cart">Your cart is empty</p>';
            return;
        }

        // VULNERABLE: Building HTML from potentially manipulated data
        const cartHTML = `
            <div class="cart-items">
                ${this.cart.items.map(item => this.renderCartItem(item)).join('')}
            </div>
            <div class="cart-summary">
                <div class="subtotal">
                    <span>Subtotal:</span>
                    <span>${formatCurrency(this.calculateCartTotal())}</span>
                </div>
                <button id="btn-checkout" class="btn btn-primary">Proceed to Checkout</button>
            </div>
        `;

        // VULNERABLE: innerHTML injection
        renderHTML('cart-container', cartHTML);
        this.setupEventListeners();
    }

    /**
     * VULNERABILITY: Item data rendered without sanitization
     */
    renderCartItem(item) {
        const itemTotal = parseFloat(item.price) * parseInt(item.quantity);

        // VULNERABLE: User-controlled data in HTML
        return `
            <div class="cart-item" data-id="${item.productId}">
                <div class="item-info">
                    <h4>${item.name}</h4>
                    <p class="item-price">Price: ${formatCurrency(item.price)}</p>
                </div>
                <div class="item-quantity">
                    <label>Quantity:</label>
                    <input type="number" value="${item.quantity}" 
                           class="quantity-input" 
                           data-id="${item.productId}"
                           onchange="window.cartManager.updateQuantity('${item.productId}', this.value)">
                    <button class="btn-update-quantity" data-id="${item.productId}">Update</button>
                </div>
                <div class="item-total">
                    <span>${formatCurrency(itemTotal)}</span>
                </div>
                <div class="item-actions">
                    <button class="btn-remove-item" data-id="${item.productId}">Remove</button>
                </div>
            </div>
        `;
    }

    /**
     * VULNERABILITY: Direct manipulation of item prices
     * This function allows arbitrary price changes
     */
    modifyItemPrice(productId, newPrice) {
        const item = this.cart.items.find(item => item.productId === productId);
        
        if (item) {
            // VULNERABLE: Allows direct price modification
            item.price = newPrice;
            this.saveCart();
            this.renderCart();
            
            displayMessage(`Price updated to ${formatCurrency(newPrice)}`, 'success');
        }
    }

    /**
     * VULNERABILITY: Syncs with server but trusts client data
     */
    async syncWithServer() {
        try {
            // VULNERABLE: Sends entire cart with client-side prices
            const response = await api.post('/cart/sync', {
                items: this.cart.items // Contains client-controlled prices!
            });

            if (response.success) {
                console.log('Cart synced with server');
            }
        } catch (error) {
            console.error('Failed to sync cart:', error);
        }
    }

    /**
     * VULNERABILITY: Returns cart data that can be manipulated
     */
    getCartData() {
        // VULNERABLE: Returns manipulatable cart data
        return {
            items: this.cart.items,
            total: this.calculateCartTotal(),
            itemCount: this.cart.items.reduce((count, item) => count + parseInt(item.quantity), 0)
        };
    }

    /**
     * VULNERABILITY: Clears cart without proper authorization
     */
    async clearCart() {
        this.cart.items = [];
        this.saveCart();
        this.renderCart();

        try {
            await api.delete('/cart/clear');
            displayMessage('Cart cleared', 'success');
        } catch (error) {
            displayMessage(`Failed to clear cart: ${error.message}`, 'error');
        }
    }

    /**
     * VULNERABILITY: Exports cart data with prices
     * Can be modified and re-imported
     */
    exportCart() {
        // VULNERABLE: Exports manipulatable data
        const cartData = JSON.stringify(this.cart, null, 2);
        console.log('Cart Export:', cartData);
        return cartData;
    }

    /**
     * VULNERABILITY: Imports cart data without validation
     */
    importCart(cartData) {
        try {
            // VULNERABLE: No validation of imported data
            this.cart = JSON.parse(cartData);
            this.saveCart();
            this.renderCart();
            displayMessage('Cart imported successfully', 'success');
        } catch (error) {
            displayMessage('Invalid cart data', 'error');
        }
    }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        window.cartManager = new CartManager();
    });
} else {
    window.cartManager = new CartManager();
}

export default CartManager;
