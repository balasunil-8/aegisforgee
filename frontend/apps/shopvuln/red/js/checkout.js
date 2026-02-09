/**
 * ⚠️ VULNERABLE CODE - FOR EDUCATIONAL PURPOSES ONLY ⚠️
 * 
 * ShopVuln Red Team - Checkout Process (VULNERABLE VERSION)
 * 
 * This file contains intentionally vulnerable code for security training.
 * DO NOT use this code in production environments.
 * 
 * Vulnerabilities:
 * - Payment bypass (client-side payment validation)
 * - Total amount manipulation
 * - No server-side verification
 * - Client controls payment status
 * - Order confirmation without payment
 * - Session hijacking possible
 */

import api from './api.js';
import { 
    renderHTML, 
    displayMessage, 
    formatCurrency,
    getFromStorage,
    saveToStorage,
    generateOrderId 
} from './utils.js';

class CheckoutManager {
    constructor() {
        this.cart = this.loadCart();
        this.orderTotal = 0;
        this.discounts = [];
        this.init();
    }

    init() {
        this.calculateOrderTotal();
        this.renderOrderSummary();
        this.setupEventListeners();
    }

    loadCart() {
        // VULNERABLE: Loading cart from localStorage (can be tampered)
        const cart = getFromStorage('shopping_cart');
        return cart || { items: [] };
    }

    setupEventListeners() {
        const checkoutForm = document.getElementById('checkout-form');
        const paymentMethodInputs = document.querySelectorAll('input[name="payment-method"]');
        const skipPaymentBtn = document.getElementById('skip-payment-btn');

        if (checkoutForm) {
            checkoutForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.processCheckout();
            });
        }

        paymentMethodInputs.forEach(input => {
            input.addEventListener('change', (e) => {
                this.handlePaymentMethodChange(e.target.value);
            });
        });

        // VULNERABILITY: Secret button to bypass payment
        if (skipPaymentBtn) {
            skipPaymentBtn.addEventListener('click', () => {
                this.bypassPayment();
            });
        }
    }

    /**
     * VULNERABILITY: Client-side total calculation
     * Total can be manipulated before submission
     */
    calculateOrderTotal() {
        let subtotal = 0;

        // VULNERABLE: Trusting client-side prices
        this.cart.items.forEach(item => {
            subtotal += parseFloat(item.price) * parseInt(item.quantity);
        });

        // VULNERABLE: Applying discounts without server validation
        this.discounts.forEach(discount => {
            subtotal -= discount.amount;
        });

        // VULNERABLE: Client calculates final total
        this.orderTotal = Math.max(0, subtotal);
    }

    /**
     * VULNERABILITY: Order summary rendered without sanitization
     */
    renderOrderSummary() {
        const container = document.getElementById('order-summary');
        if (!container) return;

        const summaryHTML = `
            <h3>Order Summary</h3>
            <div class="order-items">
                ${this.cart.items.map(item => `
                    <div class="order-item">
                        <span>${item.name} (x${item.quantity})</span>
                        <span>${formatCurrency(item.price * item.quantity)}</span>
                    </div>
                `).join('')}
            </div>
            <div class="order-discounts">
                ${this.discounts.map(d => `
                    <div class="discount-item">
                        <span>Discount: ${d.code}</span>
                        <span>-${formatCurrency(d.amount)}</span>
                    </div>
                `).join('')}
            </div>
            <div class="order-total">
                <strong>Total:</strong>
                <strong>${formatCurrency(this.orderTotal)}</strong>
            </div>
            <!-- VULNERABILITY: Hidden input with client-controlled total -->
            <input type="hidden" id="total-amount" value="${this.orderTotal}">
        `;

        renderHTML('order-summary', summaryHTML);
    }

    handlePaymentMethodChange(method) {
        const cardDetails = document.getElementById('card-details');
        const paypalDetails = document.getElementById('paypal-details');

        if (cardDetails) cardDetails.style.display = method === 'card' ? 'block' : 'none';
        if (paypalDetails) paypalDetails.style.display = method === 'paypal' ? 'block' : 'none';
    }

    /**
     * VULNERABILITY: Payment processing done client-side
     * No real payment validation
     */
    async processCheckout() {
        const form = document.getElementById('checkout-form');
        const formData = new FormData(form);

        // VULNERABLE: Getting total from hidden input (can be modified)
        const totalAmount = document.getElementById('total-amount').value;

        const orderData = {
            orderId: generateOrderId(), // VULNERABLE: Predictable order ID
            items: this.cart.items, // Contains client-side prices
            total: totalAmount, // Client-controlled total
            customer: {
                name: formData.get('name'),
                email: formData.get('email'),
                address: formData.get('address'),
                city: formData.get('city'),
                zip: formData.get('zip')
            },
            payment: {
                method: formData.get('payment-method'),
                // VULNERABLE: Sensitive payment info in plain text
                cardNumber: formData.get('card-number'),
                cardExpiry: formData.get('card-expiry'),
                cardCVV: formData.get('card-cvv')
            }
        };

        try {
            // VULNERABLE: Client declares payment as processed
            const paymentProcessed = this.simulatePayment(orderData.payment);

            if (paymentProcessed) {
                // VULNERABLE: Client-side payment validation
                const response = await api.post('/orders/create', {
                    ...orderData,
                    paymentStatus: 'paid', // Client sets payment status!
                    paymentVerified: true // No server verification!
                });

                if (response.success) {
                    this.handleSuccessfulOrder(response.orderId);
                }
            }
        } catch (error) {
            displayMessage(`Checkout failed: ${error.message}`, 'error');
        }
    }

    /**
     * VULNERABILITY: Payment simulation - always returns true
     * No actual payment processing or validation
     */
    simulatePayment(paymentInfo) {
        console.log('Processing payment...', paymentInfo);

        // VULNERABLE: Fake payment validation
        // Always returns true - payment can be bypassed!
        return true;
    }

    /**
     * VULNERABILITY: Direct payment bypass function
     * Allows completing order without payment
     */
    async bypassPayment() {
        console.log('⚠️ PAYMENT BYPASS ACTIVATED ⚠️');

        const orderData = {
            orderId: generateOrderId(),
            items: this.cart.items,
            total: 0, // VULNERABLE: Set total to $0
            customer: {
                name: 'Anonymous',
                email: 'bypass@example.com',
                address: 'N/A',
                city: 'N/A',
                zip: '00000'
            },
            payment: {
                method: 'bypass',
                status: 'completed' // VULNERABLE: Fake payment status
            },
            paymentStatus: 'paid', // Client declares payment complete
            paymentVerified: false // But marks as not verified
        };

        try {
            const response = await api.post('/orders/create', orderData);

            if (response.success) {
                displayMessage('⚠️ Payment bypassed! Order placed for $0', 'success');
                this.handleSuccessfulOrder(response.orderId);
            }
        } catch (error) {
            displayMessage(`Bypass failed: ${error.message}`, 'error');
        }
    }

    /**
     * VULNERABILITY: Allows manual total override
     */
    overrideTotal(newTotal) {
        // VULNERABLE: Allows arbitrary total modification
        this.orderTotal = parseFloat(newTotal);
        
        const totalInput = document.getElementById('total-amount');
        if (totalInput) {
            totalInput.value = newTotal;
        }

        this.renderOrderSummary();
        displayMessage(`Total overridden to ${formatCurrency(newTotal)}`, 'success');
    }

    /**
     * VULNERABILITY: Discount applied without validation
     */
    applyDiscount(code, amount) {
        // VULNERABLE: No server-side discount validation
        this.discounts.push({ code, amount });
        this.calculateOrderTotal();
        this.renderOrderSummary();
        
        displayMessage(`Discount ${code} applied: -${formatCurrency(amount)}`, 'success');
    }

    handleSuccessfulOrder(orderId) {
        // Save order confirmation
        saveToStorage('last_order', {
            orderId: orderId,
            total: this.orderTotal,
            date: new Date().toISOString()
        });

        // Clear cart
        saveToStorage('shopping_cart', { items: [] });

        // Redirect to confirmation
        window.location.href = `/order-confirmation.html?order=${orderId}`;
    }

    /**
     * VULNERABILITY: Order status can be changed client-side
     */
    async updateOrderStatus(orderId, status) {
        try {
            // VULNERABLE: Client can change order status
            const response = await api.put(`/orders/${orderId}/status`, {
                status: status, // No authorization check
                updatedBy: 'client' // Client updates order
            });

            if (response.success) {
                displayMessage(`Order status updated to: ${status}`, 'success');
            }
        } catch (error) {
            displayMessage(`Failed to update order: ${error.message}`, 'error');
        }
    }

    /**
     * VULNERABILITY: Order details retrieved without auth
     */
    async getOrderDetails(orderId) {
        try {
            // VULNERABLE: No authentication required
            const response = await api.get(`/orders/${orderId}`);
            return response.order;
        } catch (error) {
            console.error('Failed to get order:', error);
            return null;
        }
    }

    /**
     * VULNERABILITY: Can cancel any order by ID
     */
    async cancelOrder(orderId) {
        try {
            // VULNERABLE: No ownership verification
            const response = await api.delete(`/orders/${orderId}`);
            
            if (response.success) {
                displayMessage('Order cancelled', 'success');
            }
        } catch (error) {
            displayMessage(`Failed to cancel order: ${error.message}`, 'error');
        }
    }

    /**
     * VULNERABILITY: Generates refund without verification
     */
    async requestRefund(orderId, amount) {
        try {
            // VULNERABLE: Client can request any refund amount
            const response = await api.post(`/orders/${orderId}/refund`, {
                amount: amount, // Client-specified amount
                reason: 'Customer request',
                autoApprove: true // Auto-approve from client!
            });

            if (response.success) {
                displayMessage(`Refund of ${formatCurrency(amount)} requested`, 'success');
            }
        } catch (error) {
            displayMessage(`Refund failed: ${error.message}`, 'error');
        }
    }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        window.checkoutManager = new CheckoutManager();
    });
} else {
    window.checkoutManager = new CheckoutManager();
}

export default CheckoutManager;
