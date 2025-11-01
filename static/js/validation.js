
// Email validation
function validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

// Password validation
function validatePassword(password) {
    const checks = {
        length: password.length >= 8,
        uppercase: /[A-Z]/.test(password),
        lowercase: /[a-z]/.test(password),
        number: /\d/.test(password),
        special: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)
    };
    
    const allValid = Object.values(checks).every(check => check);
    
    if (!checks.length) {
        return { valid: false, message: 'Password must be at least 8 characters long' };
    }
    if (!checks.uppercase) {
        return { valid: false, message: 'Password must contain at least one uppercase letter' };
    }
    if (!checks.lowercase) {
        return { valid: false, message: 'Password must contain at least one lowercase letter' };
    }
    if (!checks.number) {
        return { valid: false, message: 'Password must contain at least one number' };
    }
    if (!checks.special) {
        return { valid: false, message: 'Password must contain at least one special character' };
    }
    
    return { valid: true, message: 'Password is strong' };
}

// Show error for specific field
function showError(fieldId, message) {
    const errorElement = document.getElementById(fieldId);
    if (errorElement) {
        errorElement.textContent = message;
        errorElement.style.display = 'block';
    }
    
    // Add error class to input
    const inputField = document.getElementById(fieldId.replace('Error', ''));
    if (inputField) {
        inputField.classList.add('error');
    }
}

// Clear error for specific field
function clearError(fieldId) {
    const errorElement = document.getElementById(fieldId);
    if (errorElement) {
        errorElement.textContent = '';
        errorElement.style.display = 'none';
    }
    
    // Remove error class from input
    const inputField = document.getElementById(fieldId.replace('Error', ''));
    if (inputField) {
        inputField.classList.remove('error');
    }
}

// Show loading state for button
function showLoading(buttonId) {
    const button = document.getElementById(buttonId);
    if (button) {
        button.classList.add('loading');
        button.disabled = true;
    }
}

// Hide loading state for button
function hideLoading(buttonId) {
    const button = document.getElementById(buttonId);
    if (button) {
        button.classList.remove('loading');
        button.disabled = false;
    }
}

// Show success message
function showSuccess(message) {
    showNotification(message, 'success');
}

// Show notification
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `flash flash-${type}`;
    notification.innerHTML = `
        <span>${message}</span>
        <button class="flash-close" onclick="this.parentElement.remove()">
            <i class="fas fa-times"></i>
        </button>
    `;
    
    // Create container if it doesn't exist
    let container = document.querySelector('.flash-container');
    if (!container) {
        container = document.createElement('div');
        container.className = 'flash-container';
        document.body.appendChild(container);
    }
    
    container.appendChild(notification);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        notification.remove();
    }, 5000);
}

// Show info message
function showInfo(message) {
    showNotification(message, 'info');
}

// Show warning message
function showWarning(message) {
    showNotification(message, 'warning');
}

// Show error message (global)
function showErrorNotification(message) {
    showNotification(message, 'error');
}
