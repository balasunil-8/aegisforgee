/**
 * BLUE TEAM - SECURE Products Handler for ShopVuln
 * 
 * SECURITY FIXES FROM RED TEAM:
 * ✓ Removed SQL injection vulnerabilities - all queries are parameterized server-side
 * ✓ Input sanitization on search queries
 * ✓ XSS prevention using textContent instead of innerHTML
 * ✓ Proper output encoding for product data
 * ✓ Server-side validation for all product operations
 * ✓ No client-side price manipulation possible
 * ✓ Rate limiting on search queries
 * ✓ Secure image URL validation
 * 
 * This file handles product display and search with security best practices.
 */

const SecureProducts = {
    currentCategory: 'all',
    currentPage: 1,
    productsPerPage: 12,
    searchTimeout: null,
    
    /**
     * Initialize products page
     */
    async init() {
        this.setupEventListeners();
        await this.loadProducts();
    },
    
    /**
     * Setup event listeners
     */
    setupEventListeners() {
        // Search input with debouncing to prevent excessive requests
        const searchInput = document.getElementById('product-search');
        if (searchInput) {
            searchInput.addEventListener('input', SecureUtils.debounce((e) => {
                this.handleSearch(e.target.value);
            }, 500));
        }
        
        // Category filter
        const categoryButtons = document.querySelectorAll('[data-category]');
        categoryButtons.forEach(button => {
            button.addEventListener('click', (e) => {
                e.preventDefault();
                const category = e.target.dataset.category;
                this.filterByCategory(category);
            });
        });
        
        // Sort dropdown
        const sortSelect = document.getElementById('product-sort');
        if (sortSelect) {
            sortSelect.addEventListener('change', (e) => {
                this.sortProducts(e.target.value);
            });
        }
    },
    
    /**
     * Load products from API
     */
    async loadProducts(params = {}) {
        try {
            const loadingEl = document.getElementById('products-loading');
            const containerEl = document.getElementById('products-container');
            
            if (loadingEl) loadingEl.style.display = 'block';
            if (containerEl) containerEl.innerHTML = '';
            
            // Build query parameters
            const queryParams = {
                page: this.currentPage,
                per_page: this.productsPerPage,
                ...params
            };
            
            if (this.currentCategory !== 'all') {
                queryParams.category = this.currentCategory;
            }
            
            const response = await SecureAPI.products.getAll(queryParams);
            
            if (loadingEl) loadingEl.style.display = 'none';
            
            if (response.success && response.data) {
                this.renderProducts(response.data.products || response.data);
                
                if (response.data.total) {
                    this.renderPagination(response.data.total);
                }
            } else {
                this.showError('Failed to load products');
            }
            
        } catch (error) {
            console.error('Error loading products:', error);
            this.showError('Failed to load products. Please try again.');
            
            const loadingEl = document.getElementById('products-loading');
            if (loadingEl) loadingEl.style.display = 'none';
        }
    },
    
    /**
     * Render products to the page
     */
    renderProducts(products) {
        const container = document.getElementById('products-container');
        if (!container) return;
        
        container.innerHTML = '';
        
        if (!products || products.length === 0) {
            container.appendChild(
                SecureUtils.createElementWithText('p', 'No products found.', 'text-center text-muted')
            );
            return;
        }
        
        products.forEach(product => {
            const productCard = this.createProductCard(product);
            container.appendChild(productCard);
        });
    },
    
    /**
     * Create a secure product card
     */
    createProductCard(product) {
        const card = document.createElement('div');
        card.className = 'col-md-4 col-sm-6 mb-4';
        
        const cardInner = document.createElement('div');
        cardInner.className = 'card h-100 product-card';
        
        // Product image with validation
        const imgContainer = document.createElement('div');
        imgContainer.className = 'card-img-top-container';
        
        const img = document.createElement('img');
        img.className = 'card-img-top';
        // Validate and sanitize image URL
        img.src = this.validateImageURL(product.image) || '/static/images/placeholder.jpg';
        img.alt = SecureUtils.sanitizeInput(product.name, 100);
        img.loading = 'lazy';
        
        imgContainer.appendChild(img);
        cardInner.appendChild(imgContainer);
        
        // Card body
        const cardBody = document.createElement('div');
        cardBody.className = 'card-body d-flex flex-column';
        
        // Product name - use textContent to prevent XSS
        const title = document.createElement('h5');
        title.className = 'card-title';
        title.textContent = SecureUtils.sanitizeInput(product.name, 100);
        cardBody.appendChild(title);
        
        // Product description - use textContent to prevent XSS
        const description = document.createElement('p');
        description.className = 'card-text';
        description.textContent = SecureUtils.sanitizeInput(product.description, 200);
        cardBody.appendChild(description);
        
        // Category badge
        if (product.category) {
            const badge = document.createElement('span');
            badge.className = 'badge bg-secondary mb-2';
            badge.textContent = SecureUtils.sanitizeInput(product.category, 50);
            cardBody.appendChild(badge);
        }
        
        // Price and rating container
        const priceContainer = document.createElement('div');
        priceContainer.className = 'mt-auto';
        
        // Price - server-side validated, display only
        const price = document.createElement('p');
        price.className = 'h4 text-primary mb-2';
        price.textContent = SecureUtils.formatPrice(product.price);
        priceContainer.appendChild(price);
        
        // Rating
        if (product.rating !== undefined) {
            const rating = this.createRatingStars(product.rating);
            priceContainer.appendChild(rating);
        }
        
        cardBody.appendChild(priceContainer);
        
        // Add to cart button
        const btnGroup = document.createElement('div');
        btnGroup.className = 'btn-group mt-3 w-100';
        
        const viewBtn = document.createElement('button');
        viewBtn.className = 'btn btn-outline-primary';
        viewBtn.textContent = 'View Details';
        viewBtn.onclick = (e) => {
            e.preventDefault();
            this.viewProductDetails(product.id);
        };
        
        const addToCartBtn = document.createElement('button');
        addToCartBtn.className = 'btn btn-primary';
        addToCartBtn.textContent = 'Add to Cart';
        addToCartBtn.onclick = async (e) => {
            e.preventDefault();
            await this.addToCart(product.id);
        };
        
        btnGroup.appendChild(viewBtn);
        btnGroup.appendChild(addToCartBtn);
        cardBody.appendChild(btnGroup);
        
        cardInner.appendChild(cardBody);
        card.appendChild(cardInner);
        
        return card;
    },
    
    /**
     * Create rating stars display
     */
    createRatingStars(rating) {
        const container = document.createElement('div');
        container.className = 'rating';
        
        const numRating = Math.min(5, Math.max(0, parseFloat(rating) || 0));
        const fullStars = Math.floor(numRating);
        const hasHalfStar = numRating % 1 >= 0.5;
        
        for (let i = 0; i < 5; i++) {
            const star = document.createElement('span');
            if (i < fullStars) {
                star.textContent = '★';
                star.className = 'star-filled';
            } else if (i === fullStars && hasHalfStar) {
                star.textContent = '⯨';
                star.className = 'star-half';
            } else {
                star.textContent = '☆';
                star.className = 'star-empty';
            }
            container.appendChild(star);
        }
        
        const ratingText = document.createElement('span');
        ratingText.className = 'ms-2 text-muted';
        ratingText.textContent = `(${numRating.toFixed(1)})`;
        container.appendChild(ratingText);
        
        return container;
    },
    
    /**
     * Validate image URL to prevent malicious URLs
     */
    validateImageURL(url) {
        if (!url || typeof url !== 'string') return null;
        
        // Only allow http(s) protocols and relative URLs
        try {
            if (url.startsWith('/')) return url;
            const urlObj = new URL(url);
            if (urlObj.protocol === 'http:' || urlObj.protocol === 'https:') {
                return url;
            }
        } catch (e) {
            return null;
        }
        
        return null;
    },
    
    /**
     * Handle search with input sanitization
     */
    async handleSearch(query) {
        // Sanitize search query
        const sanitizedQuery = SecureUtils.sanitizeInput(query, 100);
        
        if (sanitizedQuery.length < 2 && sanitizedQuery.length > 0) {
            return; // Minimum 2 characters
        }
        
        try {
            if (sanitizedQuery.length === 0) {
                await this.loadProducts();
            } else {
                const response = await SecureAPI.products.search(sanitizedQuery);
                if (response.success) {
                    this.renderProducts(response.data.products || response.data);
                }
            }
        } catch (error) {
            console.error('Search error:', error);
            this.showError('Search failed. Please try again.');
        }
    },
    
    /**
     * Filter products by category
     */
    async filterByCategory(category) {
        this.currentCategory = category;
        this.currentPage = 1;
        await this.loadProducts();
    },
    
    /**
     * Sort products
     */
    async sortProducts(sortBy) {
        await this.loadProducts({ sort: sortBy });
    },
    
    /**
     * View product details
     */
    async viewProductDetails(productId) {
        window.location.href = `/shopvuln/product/${encodeURIComponent(productId)}`;
    },
    
    /**
     * Add product to cart
     */
    async addToCart(productId) {
        try {
            const response = await SecureAPI.cart.add(productId, 1);
            
            if (response.success) {
                SecureUtils.showSuccess('Product added to cart!');
                // Update cart count if element exists
                this.updateCartCount();
            } else {
                SecureUtils.showError(response.message || 'Failed to add to cart');
            }
        } catch (error) {
            console.error('Add to cart error:', error);
            SecureUtils.showError('Failed to add to cart. Please try again.');
        }
    },
    
    /**
     * Update cart count in header
     */
    async updateCartCount() {
        try {
            const response = await SecureAPI.cart.get();
            if (response.success && response.data) {
                const cartCount = document.getElementById('cart-count');
                if (cartCount) {
                    const itemCount = response.data.items?.length || 0;
                    cartCount.textContent = itemCount;
                    if (itemCount > 0) {
                        cartCount.style.display = 'inline';
                    }
                }
            }
        } catch (error) {
            console.error('Error updating cart count:', error);
        }
    },
    
    /**
     * Render pagination
     */
    renderPagination(totalProducts) {
        const container = document.getElementById('pagination-container');
        if (!container) return;
        
        const totalPages = Math.ceil(totalProducts / this.productsPerPage);
        if (totalPages <= 1) {
            container.innerHTML = '';
            return;
        }
        
        container.innerHTML = '';
        const nav = document.createElement('nav');
        const ul = document.createElement('ul');
        ul.className = 'pagination justify-content-center';
        
        for (let i = 1; i <= totalPages; i++) {
            const li = document.createElement('li');
            li.className = `page-item ${i === this.currentPage ? 'active' : ''}`;
            
            const a = document.createElement('a');
            a.className = 'page-link';
            a.href = '#';
            a.textContent = i;
            a.onclick = async (e) => {
                e.preventDefault();
                this.currentPage = i;
                await this.loadProducts();
                window.scrollTo({ top: 0, behavior: 'smooth' });
            };
            
            li.appendChild(a);
            ul.appendChild(li);
        }
        
        nav.appendChild(ul);
        container.appendChild(nav);
    },
    
    /**
     * Show error message
     */
    showError(message) {
        SecureUtils.showError(message, 'products-error');
    }
};

// Initialize on page load
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => SecureProducts.init());
} else {
    SecureProducts.init();
}
