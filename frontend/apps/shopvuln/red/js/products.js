/**
 * ⚠️ VULNERABLE CODE - FOR EDUCATIONAL PURPOSES ONLY ⚠️
 * 
 * ShopVuln Red Team - Product Display & Search (VULNERABLE VERSION)
 * 
 * This file contains intentionally vulnerable code for security training.
 * DO NOT use this code in production environments.
 * 
 * Vulnerabilities:
 * - SQL Injection in search functionality
 * - XSS in product display
 * - No input validation
 * - Direct query parameter usage
 * - Client-side filtering bypass
 */

import api from './api.js';
import { renderHTML, createProductCard, displayMessage, getUrlParams, buildQueryString } from './utils.js';

class ProductManager {
    constructor() {
        this.products = [];
        this.currentPage = 1;
        this.itemsPerPage = 12;
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.loadProducts();
        this.checkUrlParams();
    }

    setupEventListeners() {
        const searchBtn = document.getElementById('search-btn');
        const searchInput = document.getElementById('search-input');
        const categoryFilter = document.getElementById('category-filter');
        const priceSort = document.getElementById('price-sort');

        if (searchBtn) {
            searchBtn.addEventListener('click', () => this.searchProducts());
        }

        if (searchInput) {
            searchInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    this.searchProducts();
                }
            });
        }

        if (categoryFilter) {
            categoryFilter.addEventListener('change', () => this.filterByCategory());
        }

        if (priceSort) {
            priceSort.addEventListener('change', () => this.sortByPrice());
        }
    }

    /**
     * VULNERABILITY: SQL Injection in search query
     * The search term is sent directly to the backend without sanitization
     */
    async searchProducts() {
        const searchInput = document.getElementById('search-input');
        const searchTerm = searchInput.value;

        // VULNERABLE: No input validation or sanitization
        // This allows SQL injection attacks like: ' OR '1'='1
        try {
            const query = buildQueryString({ search: searchTerm });
            const response = await api.get(`/products?${query}`);
            
            this.products = response.products || [];
            this.renderProducts();
            
            // VULNERABLE: Display user input without encoding
            displayMessage(`Found ${this.products.length} products for: ${searchTerm}`);
        } catch (error) {
            displayMessage(`Search failed: ${error.message}`, 'error');
        }
    }

    /**
     * VULNERABILITY: Category parameter passed without validation
     */
    async filterByCategory() {
        const categoryFilter = document.getElementById('category-filter');
        const category = categoryFilter.value;

        try {
            // VULNERABLE: Direct parameter injection
            const query = buildQueryString({ category: category });
            const response = await api.get(`/products?${query}`);
            
            this.products = response.products || [];
            this.renderProducts();
        } catch (error) {
            displayMessage(`Filter failed: ${error.message}`, 'error');
        }
    }

    /**
     * VULNERABILITY: URL parameters used without validation
     */
    checkUrlParams() {
        const params = getUrlParams();
        
        if (params.search) {
            // VULNERABLE: Using URL param directly
            const searchInput = document.getElementById('search-input');
            if (searchInput) {
                searchInput.value = params.search;
                this.searchProducts();
            }
        }

        if (params.category) {
            // VULNERABLE: Using URL param directly
            const categoryFilter = document.getElementById('category-filter');
            if (categoryFilter) {
                categoryFilter.value = params.category;
                this.filterByCategory();
            }
        }
    }

    async loadProducts() {
        try {
            const response = await api.get('/products');
            this.products = response.products || [];
            this.renderProducts();
        } catch (error) {
            displayMessage(`Failed to load products: ${error.message}`, 'error');
        }
    }

    /**
     * VULNERABILITY: XSS in product rendering
     * Product data is rendered without sanitization
     */
    renderProducts() {
        const container = document.getElementById('products-container');
        if (!container) return;

        if (this.products.length === 0) {
            // VULNERABLE: innerHTML usage
            container.innerHTML = '<p class="no-products">No products found.</p>';
            return;
        }

        // VULNERABLE: createProductCard doesn't sanitize input
        const productsHTML = this.products.map(product => createProductCard(product)).join('');
        
        // VULNERABLE: Direct innerHTML injection
        renderHTML('products-container', productsHTML);

        this.attachProductEventListeners();
    }

    attachProductEventListeners() {
        const addToCartButtons = document.querySelectorAll('.btn-add-cart');
        
        addToCartButtons.forEach(button => {
            button.addEventListener('click', (e) => {
                const productId = e.target.dataset.id;
                const productPrice = e.target.dataset.price;
                
                // VULNERABLE: Client-side price data can be manipulated
                this.addToCart(productId, productPrice);
            });
        });
    }

    /**
     * VULNERABILITY: Trusts client-side price data
     */
    async addToCart(productId, price) {
        const product = this.products.find(p => p.id == productId);
        
        if (!product) {
            displayMessage('Product not found', 'error');
            return;
        }

        try {
            // VULNERABLE: Sending client-side price to backend
            const response = await api.post('/cart/add', {
                productId: productId,
                price: price, // Price from client can be modified
                quantity: 1
            });

            if (response.success) {
                displayMessage(`${product.name} added to cart!`, 'success');
                this.updateCartCount();
            }
        } catch (error) {
            displayMessage(`Failed to add to cart: ${error.message}`, 'error');
        }
    }

    sortByPrice() {
        const priceSort = document.getElementById('price-sort');
        const direction = priceSort.value;

        if (direction === 'asc') {
            this.products.sort((a, b) => parseFloat(a.price) - parseFloat(b.price));
        } else if (direction === 'desc') {
            this.products.sort((a, b) => parseFloat(b.price) - parseFloat(a.price));
        }

        this.renderProducts();
    }

    async updateCartCount() {
        try {
            const response = await api.get('/cart');
            const count = response.items ? response.items.length : 0;
            
            const cartBadge = document.getElementById('cart-count');
            if (cartBadge) {
                cartBadge.textContent = count;
            }
        } catch (error) {
            console.error('Failed to update cart count:', error);
        }
    }

    /**
     * VULNERABILITY: Direct product details from URL
     */
    async loadProductDetails(productId) {
        try {
            // VULNERABLE: No validation of productId
            const response = await api.get(`/products/${productId}`);
            const product = response.product;

            // VULNERABLE: Render without sanitization
            const detailsHTML = `
                <div class="product-details">
                    <div class="product-gallery">
                        <img src="${product.image}" alt="${product.name}">
                    </div>
                    <div class="product-info">
                        <h1>${product.name}</h1>
                        <p class="price">$${product.price}</p>
                        <div class="description">${product.description}</div>
                        <div class="specifications">${product.specifications || ''}</div>
                        <button class="btn-add-cart" data-id="${product.id}" data-price="${product.price}">
                            Add to Cart
                        </button>
                    </div>
                </div>
            `;

            renderHTML('product-details-container', detailsHTML);
            this.attachProductEventListeners();
        } catch (error) {
            displayMessage(`Failed to load product: ${error.message}`, 'error');
        }
    }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        window.productManager = new ProductManager();
    });
} else {
    window.productManager = new ProductManager();
}

export default ProductManager;
