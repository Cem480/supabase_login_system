
// Logout function
async function logout() {
    if (!confirm('Are you sure you want to logout?')) {
        return;
    }
    
    try {
        const response = await fetch('/api/auth/logout', {
            method: 'POST'
        });
        
        if (response.ok) {
            showSuccess('Logged out successfully');
            setTimeout(() => {
                window.location.href = '/login';
            }, 1000);
        } else {
            showError('Logout failed');
        }
    } catch (error) {
        console.error('Logout error:', error);
        showError('An error occurred during logout');
    }
}

// Auto-dismiss flash messages
document.addEventListener('DOMContentLoaded', function() {
    const flashMessages = document.querySelectorAll('.flash');
    flashMessages.forEach(flash => {
        setTimeout(() => {
            flash.style.animation = 'slideOut 0.3s ease';
            setTimeout(() => flash.remove(), 300);
        }, 5000);
    });
});

// Slide out animation
const style = document.createElement('style');
style.textContent = `
    @keyframes slideOut {
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);

// Handle escape key to close modals/notifications
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        // Close flash messages
        document.querySelectorAll('.flash').forEach(flash => flash.remove());
    }
});

// API helper functions
async function apiRequest(url, options = {}) {
    const defaultOptions = {
        headers: {
            'Content-Type': 'application/json'
        }
    };
    
    const mergedOptions = {
        ...defaultOptions,
        ...options,
        headers: {
            ...defaultOptions.headers,
            ...options.headers
        }
    };
    
    try {
        const response = await fetch(url, mergedOptions);
        const data = await response.json();
        
        return {
            ok: response.ok,
            status: response.status,
            data: data
        };
    } catch (error) {
        console.error('API request error:', error);
        return {
            ok: false,
            status: 500,
            data: { error: 'Network error occurred' }
        };
    }
}

// Format date helper
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

// Debounce function for search/filter inputs
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Copy to clipboard
async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        showSuccess('Copied to clipboard!');
    } catch (error) {
        console.error('Copy failed:', error);
        showError('Failed to copy');
    }
}

// Check if user is authenticated
function isAuthenticated() {
    // Check for auth cookie
    return document.cookie.includes('auth_token');
}

// Redirect if not authenticated
function requireAuth() {
    if (!isAuthenticated()) {
        window.location.href = '/login';
    }
}

// Smooth scroll to element
function smoothScrollTo(elementId) {
    const element = document.getElementById(elementId);
    if (element) {
        element.scrollIntoView({
            behavior: 'smooth',
            block: 'start'
        });
    }
}

// Form submission helper
async function submitForm(formId, url, method = 'POST') {
    const form = document.getElementById(formId);
    if (!form) return;
    
    const formData = new FormData(form);
    const data = Object.fromEntries(formData);
    
    const response = await apiRequest(url, {
        method: method,
        body: JSON.stringify(data)
    });
    
    return response;
}

// Initialize tooltips (if needed)
function initTooltips() {
    const tooltips = document.querySelectorAll('[data-tooltip]');
    tooltips.forEach(element => {
        element.addEventListener('mouseenter', function() {
            const tooltip = document.createElement('div');
            tooltip.className = 'tooltip';
            tooltip.textContent = this.dataset.tooltip;
            document.body.appendChild(tooltip);
            
            const rect = this.getBoundingClientRect();
            tooltip.style.top = (rect.top - tooltip.offsetHeight - 5) + 'px';
            tooltip.style.left = (rect.left + rect.width / 2 - tooltip.offsetWidth / 2) + 'px';
        });
        
        element.addEventListener('mouseleave', function() {
            document.querySelectorAll('.tooltip').forEach(t => t.remove());
        });
    });
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    // Initialize any tooltips
    initTooltips();
    
    // Add loading class to body during page transitions
    const links = document.querySelectorAll('a[href^="/"]');
    links.forEach(link => {
        link.addEventListener('click', function(e) {
            if (!e.ctrlKey && !e.metaKey && !this.target) {
                document.body.classList.add('loading');
            }
        });
    });
});

// Console welcome message
console.log('%c🚀 Supabase Login System', 'font-size: 20px; color: #10B981; font-weight: bold;');
console.log('%cCS411 Software Architecture Design Project', 'font-size: 12px; color: #6B7280;');
console.log('%cBuilt with Flask + PostgreSQL + JWT', 'font-size: 12px; color: #6B7280;');
