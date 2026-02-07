/**
 * SecureBank Authentication Logic
 * Handles login, logout, and session management
 * 
 * RED TEAM VERSION - Contains client-side vulnerabilities
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

// Handle Enter key in password field
document.getElementById('password').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        document.getElementById('login-form').dispatchEvent(new Event('submit'));
    }
});

// Add visual feedback for demo SQL injection
const usernameInput = document.getElementById('username');
usernameInput.addEventListener('input', (e) => {
    const value = e.target.value;
    
    // Detect SQL injection patterns
    const sqlPatterns = [
        /'/gi,
        /--/gi,
        /OR/gi,
        /AND/gi,
        /=/gi,
        /;/gi,
        /UNION/gi,
        /SELECT/gi,
        /DROP/gi,
        /INSERT/gi,
        /UPDATE/gi,
        /DELETE/gi
    ];
    
    let hasSQLKeywords = false;
    for (const pattern of sqlPatterns) {
        if (pattern.test(value)) {
            hasSQLKeywords = true;
            break;
        }
    }
    
    // Visual feedback for potential SQL injection attempt
    if (hasSQLKeywords) {
        usernameInput.style.borderColor = '#ff9800';
        usernameInput.style.boxShadow = '0 0 0 3px rgba(255, 152, 0, 0.1)';
        
        // Show hint
        const existingHint = document.getElementById('sql-hint');
        if (!existingHint) {
            const hint = document.createElement('div');
            hint.id = 'sql-hint';
            hint.className = 'alert alert-warning';
            hint.style.marginTop = '10px';
            hint.innerHTML = '⚠️ SQL keywords detected! This is the <strong>vulnerable version</strong> - try: <code>admin\' OR \'1\'=\'1\'--</code>';
            usernameInput.parentElement.appendChild(hint);
        }
    } else {
        usernameInput.style.borderColor = '';
        usernameInput.style.boxShadow = '';
        
        const existingHint = document.getElementById('sql-hint');
        if (existingHint) {
            existingHint.remove();
        }
    }
});

// Add quick-fill buttons for testing (demo purposes)
function addQuickFillButtons() {
    const testCredsDiv = document.querySelector('.test-credentials');
    if (!testCredsDiv) return;
    
    const buttonsHTML = `
        <div style="margin-top: 12px; display: flex; gap: 8px; flex-wrap: wrap;">
            <button type="button" class="btn btn-small btn-secondary" onclick="quickFill('alice', 'password123')">
                Fill Alice
            </button>
            <button type="button" class="btn btn-small btn-secondary" onclick="quickFill('bob', 'securepass456')">
                Fill Bob
            </button>
            <button type="button" class="btn btn-small btn-danger" onclick="quickFill(\`admin' OR '1'='1'--\`, 'anything')">
                SQL Injection
            </button>
        </div>
    `;
    
    testCredsDiv.innerHTML += buttonsHTML;
}

// Quick fill function
window.quickFill = function(username, password) {
    document.getElementById('username').value = username;
    document.getElementById('password').value = password;
    
    // Trigger input event for visual feedback
    document.getElementById('username').dispatchEvent(new Event('input'));
    
    showAlert('Credentials filled! Click "Sign In" to continue.', 'info');
};

// Initialize quick-fill buttons
document.addEventListener('DOMContentLoaded', () => {
    addQuickFillButtons();
});

// Log team mode for debugging
console.log('🏦 SecureBank Login Page');
console.log('Team Mode:', getTeamMode());
console.log('API Base URL:', getApiBaseUrl());

// Add warning banner for Red Team
if (getTeamMode() === 'red') {
    console.log('%c⚠️ WARNING: RED TEAM (VULNERABLE) VERSION', 'background: #ff0000; color: white; padding: 10px; font-size: 16px; font-weight: bold;');
    console.log('This version contains intentional security vulnerabilities for educational purposes.');
    console.log('Try SQL injection: admin\' OR \'1\'=\'1\'--');
}
