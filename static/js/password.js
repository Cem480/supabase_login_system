
function updatePasswordStrength(password) {
    // Get elements
    const strengthMeter = document.getElementById('strengthMeterFill');
    const strengthText = document.getElementById('strengthText');
    
    // Requirements elements
    const reqLength = document.getElementById('req-length');
    const reqUppercase = document.getElementById('req-uppercase');
    const reqLowercase = document.getElementById('req-lowercase');
    const reqNumber = document.getElementById('req-number');
    const reqSpecial = document.getElementById('req-special');
    
    if (!password) {
        strengthMeter.style.width = '0%';
        strengthMeter.style.backgroundColor = '#E5E7EB';
        strengthText.textContent = 'Enter a password';
        strengthText.style.color = '#6B7280';
        
        // Reset requirements
        [reqLength, reqUppercase, reqLowercase, reqNumber, reqSpecial].forEach(req => {
            if (req) req.classList.remove('met');
        });
        return;
    }
    
    // Check requirements
    const checks = {
        length: password.length >= 8,
        uppercase: /[A-Z]/.test(password),
        lowercase: /[a-z]/.test(password),
        number: /\d/.test(password),
        special: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)
    };
    
    // Update requirement indicators
    if (reqLength) {
        reqLength.classList.toggle('met', checks.length);
    }
    if (reqUppercase) {
        reqUppercase.classList.toggle('met', checks.uppercase);
    }
    if (reqLowercase) {
        reqLowercase.classList.toggle('met', checks.lowercase);
    }
    if (reqNumber) {
        reqNumber.classList.toggle('met', checks.number);
    }
    if (reqSpecial) {
        reqSpecial.classList.toggle('met', checks.special);
    }
    
    // Calculate strength
    const metRequirements = Object.values(checks).filter(Boolean).length;
    const strengthPercentage = (metRequirements / 5) * 100;
    
    // Update meter
    strengthMeter.style.width = strengthPercentage + '%';
    
    // Set color and text based on strength
    if (metRequirements === 5) {
        strengthMeter.style.backgroundColor = '#22C55E'; // Green
        strengthText.textContent = 'Strong password';
        strengthText.style.color = '#22C55E';
    } else if (metRequirements >= 3) {
        strengthMeter.style.backgroundColor = '#F59E0B'; // Orange
        strengthText.textContent = 'Medium password';
        strengthText.style.color = '#F59E0B';
    } else {
        strengthMeter.style.backgroundColor = '#EF4444'; // Red
        strengthText.textContent = 'Weak password';
        strengthText.style.color = '#EF4444';
    }
}

// Calculate password score (0-100)
function calculatePasswordScore(password) {
    let score = 0;
    
    // Length score (up to 30 points)
    if (password.length >= 8) score += 10;
    if (password.length >= 12) score += 10;
    if (password.length >= 16) score += 10;
    
    // Character variety (up to 40 points)
    if (/[a-z]/.test(password)) score += 10;
    if (/[A-Z]/.test(password)) score += 10;
    if (/\d/.test(password)) score += 10;
    if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) score += 10;
    
    // Complexity bonus (up to 30 points)
    const uniqueChars = new Set(password).size;
    if (uniqueChars >= 8) score += 10;
    if (uniqueChars >= 12) score += 10;
    if (!/(.)\\1{2,}/.test(password)) score += 10; // No repeated characters
    
    return Math.min(score, 100);
}

// Check for common passwords
function isCommonPassword(password) {
    const commonPasswords = [
        'password', '123456', '123456789', 'qwerty', 'abc123',
        'password123', '12345678', '111111', '123123', 'admin',
        'letmein', 'welcome', 'monkey', 'dragon', 'master'
    ];
    
    return commonPasswords.includes(password.toLowerCase());
}

// Get password strength label
function getPasswordStrengthLabel(score) {
    if (score >= 80) return 'Very Strong';
    if (score >= 60) return 'Strong';
    if (score >= 40) return 'Medium';
    if (score >= 20) return 'Weak';
    return 'Very Weak';
}
