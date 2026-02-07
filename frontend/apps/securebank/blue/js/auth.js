/**
 * SecureBank Authentication Logic
 * Handles login, logout, and session management
 * 
 * BLUE TEAM VERSION - Secure implementation with proper validation
 */

// Redirect if already authenticated
redirectIfAuth('dashboard.html');

// Handle login form submission
document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    
    // Clear previous alerts
    const alertContainer = document.getElementById('alert-container');
    if (alertContainer) {
        alertContainer.innerHTML = '';
    }
    
    // Validate inputs
    if (!username || !password) {
        showAlert('Please enter both username and password', 'error');
        return;
    }
    
    try {
        showLoading();
        
        // Make login request
        const data = await apiRequest('/login', {
            method: 'POST',
            body: JSON.stringify({
                username: username,
                password: password
            })
        });
        
        hideLoading();
        
        if (data.success) {
            // Store session data
            setSession({
                user: data.user,
                authenticated: true,
                timestamp: new Date().toISOString()
            });
            
            // Store CSRF token if provided (Blue Team)
            if (data.csrf_token) {
                setCSRFToken(data.csrf_token);
            }
            
            // Show success message
            showAlert('Login successful! Redirecting...', 'success');
            
            // Redirect to dashboard after short delay
            setTimeout(() => {
                window.location.href = 'dashboard.html';
            }, 1000);
        } else {
            showAlert(data.error || 'Login failed', 'error');
        }
        
    } catch (error) {
        hideLoading();
        console.error('Login error:', error);
        showAlert(error.message || 'An error occurred during login', 'error');
    }
});

// Remove SQL injection visual feedback - SECURE VERSION
// No client-side detection of SQL patterns

// Log team mode for debugging
console.log('🏦 SecureBank Login Page');
console.log('Team Mode:', getTeamMode());
console.log('API Base URL:', getApiBaseUrl());

// Add info banner for Blue Team
if (getTeamMode() === 'blue') {
    console.log('%c✓ BLUE TEAM (SECURE) VERSION', 'background: #1976d2; color: white; padding: 10px; font-size: 16px; font-weight: bold;');
    console.log('This version implements proper security controls:');
    console.log('- Parameterized queries prevent SQL injection');
    console.log('- CSRF token protection');
    console.log('- Secure session management');
    console.log('- Input validation and sanitization');
}
