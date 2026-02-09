/**
 * ⚠️ VULNERABLE CODE - FOR EDUCATIONAL PURPOSES ONLY ⚠️
 * 
 * ShopVuln Red Team - Product Reviews (VULNERABLE VERSION)
 * 
 * This file contains intentionally vulnerable code for security training.
 * DO NOT use this code in production environments.
 * 
 * Vulnerabilities:
 * - XSS (Cross-Site Scripting) in review content
 * - No HTML sanitization
 * - Direct innerHTML injection
 * - Script execution via review content
 * - Event handler injection
 * - No input validation
 */

import api from './api.js';
import { renderHTML, createReviewCard, displayMessage } from './utils.js';

class ReviewManager {
    constructor(productId) {
        this.productId = productId;
        this.reviews = [];
        this.init();
    }

    init() {
        this.loadReviews();
        this.setupEventListeners();
    }

    setupEventListeners() {
        const reviewForm = document.getElementById('review-form');
        const ratingStars = document.querySelectorAll('.rating-star');

        if (reviewForm) {
            reviewForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.submitReview();
            });
        }

        ratingStars.forEach((star, index) => {
            star.addEventListener('click', () => {
                this.setRating(index + 1);
            });
        });
    }

    setRating(rating) {
        const ratingInput = document.getElementById('rating-input');
        if (ratingInput) {
            ratingInput.value = rating;
        }

        const stars = document.querySelectorAll('.rating-star');
        stars.forEach((star, index) => {
            star.classList.toggle('active', index < rating);
        });
    }

    async loadReviews() {
        try {
            const response = await api.get(`/reviews/product/${this.productId}`);
            this.reviews = response.reviews || [];
            this.renderReviews();
        } catch (error) {
            displayMessage(`Failed to load reviews: ${error.message}`, 'error');
        }
    }

    /**
     * VULNERABILITY: XSS - Reviews rendered without sanitization
     * User-submitted content is directly injected into the DOM
     */
    renderReviews() {
        const container = document.getElementById('reviews-container');
        if (!container) return;

        if (this.reviews.length === 0) {
            container.innerHTML = '<p class="no-reviews">No reviews yet. Be the first to review!</p>';
            return;
        }

        // VULNERABLE: createReviewCard doesn't sanitize content
        const reviewsHTML = this.reviews.map(review => {
            // EXTREMELY VULNERABLE: Direct HTML injection
            return `
                <div class="review" data-id="${review.id}">
                    <div class="review-header">
                        <div class="review-author">${review.author}</div>
                        <div class="review-rating">${this.renderStars(review.rating)}</div>
                        <div class="review-date">${review.date}</div>
                    </div>
                    <div class="review-title">
                        ${review.title}
                    </div>
                    <div class="review-content">
                        ${review.content}
                    </div>
                    ${review.image ? `<div class="review-image"><img src="${review.image}"></div>` : ''}
                    <div class="review-actions">
                        <button onclick="${review.helpfulCallback || 'void(0)'}" class="btn-helpful">
                            Helpful (${review.helpfulCount || 0})
                        </button>
                        <button onclick="window.reviewManager.reportReview('${review.id}')" class="btn-report">
                            Report
                        </button>
                    </div>
                </div>
            `;
        }).join('');

        // VULNERABLE: Direct innerHTML injection allows script execution
        renderHTML('reviews-container', reviewsHTML);
    }

    renderStars(rating) {
        // VULNERABLE: No validation of rating value
        return '⭐'.repeat(parseInt(rating));
    }

    /**
     * VULNERABILITY: XSS - Review submission without sanitization
     * All user input is accepted and rendered as-is
     */
    async submitReview() {
        const form = document.getElementById('review-form');
        const formData = new FormData(form);

        // VULNERABLE: Reading form data without any sanitization
        const reviewData = {
            productId: this.productId,
            author: formData.get('author'), // No sanitization
            email: formData.get('email'),
            rating: formData.get('rating'),
            title: formData.get('title'), // XSS possible
            content: formData.get('content'), // XSS possible - main attack vector
            image: formData.get('image-url'), // Could load malicious images
            helpfulCallback: formData.get('callback') // EXTREMELY DANGEROUS
        };

        try {
            // VULNERABLE: Sending unsanitized data to server
            const response = await api.post('/reviews/submit', reviewData);

            if (response.success) {
                // VULNERABLE: Display user input without encoding
                displayMessage(`Thank you for your review, ${reviewData.author}!`, 'success');
                
                // Add review to local array
                this.reviews.unshift({
                    id: response.reviewId,
                    ...reviewData,
                    date: new Date().toLocaleDateString(),
                    helpfulCount: 0
                });

                // VULNERABLE: Re-render with new unsanitized content
                this.renderReviews();
                
                form.reset();
            }
        } catch (error) {
            displayMessage(`Failed to submit review: ${error.message}`, 'error');
        }
    }

    /**
     * VULNERABILITY: Helpful counter can be manipulated
     */
    async markHelpful(reviewId) {
        const review = this.reviews.find(r => r.id === reviewId);
        
        if (review) {
            // VULNERABLE: No verification of vote authenticity
            review.helpfulCount = (review.helpfulCount || 0) + 1;
            
            try {
                await api.post(`/reviews/${reviewId}/helpful`, {
                    count: review.helpfulCount // Client sends the count!
                });

                this.renderReviews();
            } catch (error) {
                console.error('Failed to mark helpful:', error);
            }
        }
    }

    /**
     * VULNERABILITY: Report function without proper validation
     */
    async reportReview(reviewId) {
        const reason = prompt('Why are you reporting this review?');
        
        if (reason) {
            try {
                // VULNERABLE: Reason not sanitized
                await api.post(`/reviews/${reviewId}/report`, {
                    reason: reason, // Could contain malicious content
                    reportedBy: 'anonymous'
                });

                // VULNERABLE: User input in message
                displayMessage(`Review reported: ${reason}`, 'success');
            } catch (error) {
                displayMessage(`Failed to report: ${error.message}`, 'error');
            }
        }
    }

    /**
     * VULNERABILITY: Edit review allows HTML injection
     */
    async editReview(reviewId) {
        const review = this.reviews.find(r => r.id === reviewId);
        
        if (!review) return;

        // VULNERABLE: Prompts can be manipulated
        const newTitle = prompt('Edit title:', review.title);
        const newContent = prompt('Edit content:', review.content);

        if (newTitle && newContent) {
            try {
                // VULNERABLE: No sanitization of edited content
                await api.put(`/reviews/${reviewId}`, {
                    title: newTitle,
                    content: newContent
                });

                review.title = newTitle;
                review.content = newContent;
                
                this.renderReviews();
                displayMessage('Review updated', 'success');
            } catch (error) {
                displayMessage(`Failed to update: ${error.message}`, 'error');
            }
        }
    }

    /**
     * VULNERABILITY: Delete without proper authorization
     */
    async deleteReview(reviewId) {
        if (confirm('Delete this review?')) {
            try {
                // VULNERABLE: No ownership verification
                await api.delete(`/reviews/${reviewId}`);

                this.reviews = this.reviews.filter(r => r.id !== reviewId);
                this.renderReviews();
                
                displayMessage('Review deleted', 'success');
            } catch (error) {
                displayMessage(`Failed to delete: ${error.message}`, 'error');
            }
        }
    }

    /**
     * VULNERABILITY: Loads and executes review template
     */
    async loadReviewTemplate(templateUrl) {
        try {
            // EXTREMELY VULNERABLE: Fetches and executes remote content
            const response = await fetch(templateUrl);
            const template = await response.text();
            
            // DANGEROUS: Directly inserting remote content
            const container = document.getElementById('review-template');
            if (container) {
                container.innerHTML = template; // XSS via remote template
            }
        } catch (error) {
            console.error('Failed to load template:', error);
        }
    }

    /**
     * VULNERABILITY: Search reviews without sanitization
     */
    searchReviews(query) {
        // VULNERABLE: Query used directly in display
        const filtered = this.reviews.filter(review => {
            return review.content.includes(query) || 
                   review.title.includes(query) || 
                   review.author.includes(query);
        });

        const container = document.getElementById('reviews-container');
        if (container) {
            // VULNERABLE: Query displayed without encoding
            const html = `
                <div class="search-results">
                    <h3>Search results for: ${query}</h3>
                    ${filtered.map(review => createReviewCard(review)).join('')}
                </div>
            `;
            container.innerHTML = html;
        }
    }

    /**
     * VULNERABILITY: Sort parameter from URL without validation
     */
    sortReviews(sortBy) {
        // VULNERABLE: Sort parameter could be malicious
        const sortFn = new Function('a', 'b', `return ${sortBy}`);
        
        try {
            // DANGEROUS: Executing user-controlled sort function
            this.reviews.sort(sortFn);
            this.renderReviews();
        } catch (error) {
            console.error('Sort failed:', error);
        }
    }

    /**
     * VULNERABILITY: Aggregate reviews with user input
     */
    showReviewStats() {
        const stats = {
            total: this.reviews.length,
            averageRating: this.reviews.reduce((sum, r) => sum + parseInt(r.rating), 0) / this.reviews.length,
            topReviewer: this.reviews[0]?.author || 'None'
        };

        // VULNERABLE: User data in HTML
        const statsHTML = `
            <div class="review-stats">
                <h3>Review Statistics</h3>
                <p>Total Reviews: ${stats.total}</p>
                <p>Average Rating: ${stats.averageRating.toFixed(1)} ⭐</p>
                <p>Top Reviewer: ${stats.topReviewer}</p>
            </div>
        `;

        displayMessage(statsHTML, 'info');
    }
}

// Initialize with product ID from URL or page
const urlParams = new URLSearchParams(window.location.search);
const productId = urlParams.get('product') || document.body.dataset.productId;

if (productId) {
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            window.reviewManager = new ReviewManager(productId);
        });
    } else {
        window.reviewManager = new ReviewManager(productId);
    }
}

export default ReviewManager;
