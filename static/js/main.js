document.addEventListener('DOMContentLoaded', function () {
    initializeAlerts();
    initializeFormValidation();
    initializeEventListeners();
});

/**
 * Initialize auto-hiding alerts after 5 seconds
 */
function initializeAlerts() {
    const alerts = document.querySelectorAll('.alert');

    alerts.forEach(alert => {
        // Auto-hide after 5 seconds
        setTimeout(() => {
            alert.style.opacity = '1';
            alert.style.transition = 'opacity 0.3s ease';

            // Manual close can still work
        }, 5000);
    });
}

/**
 * Form validation before submission
 */
function initializeFormValidation() {
    const forms = document.querySelectorAll('form');

    forms.forEach(form => {
        // Prevent double submission
        form.addEventListener('submit', function (e) {
            const submitBtn = form.querySelector('button[type="submit"]');
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.textContent = 'Processing...';
            }
        });
    });
}

/**
 * Initialize various event listeners
 */
function initializeEventListeners() {
    // Confirm deletion actions
    const deleteButtons = document.querySelectorAll('button[type="submit"][onclick*="confirm"]');

    deleteButtons.forEach(btn => {
        btn.addEventListener('click', function (e) {
            if (!confirm('Are you sure you want to perform this action?')) {
                e.preventDefault();
            }
        });
    });
}

/**
 * Format date to readable string
 * @param {String} dateStr - ISO date string
 * @returns {String} Formatted date
 */
function formatDate(dateStr) {
    const options = { year: 'numeric', month: 'long', day: 'numeric' };
    return new Date(dateStr).toLocaleDateString('en-US', options);
}

/**
 * Format time to readable string
 * @param {String} timeStr - Time string in HH:MM format
 * @returns {String} Formatted time (e.g., "02:30 PM")
 */
function formatTime(timeStr) {
    const [hours, minutes] = timeStr.split(':');
    const hour = parseInt(hours);
    const ampm = hour >= 12 ? 'PM' : 'AM';
    const displayHour = hour % 12 || 12;
    return `${displayHour.toString().padStart(2, '0')}:${minutes} ${ampm}`;
}

/**
 * Validate email format
 * @param {String} email - Email to validate
 * @returns {Boolean} True if valid
 */
function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}

/**
 * Show a notification message
 * @param {String} message - Message to display
 * @param {String} type - Type: 'success', 'error', 'warning', 'info'
 */
function showNotification(message, type = 'info') {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type}`;
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="alert-close" onclick="this.parentElement.style.display='none';">&times;</button>
    `;

    const container = document.querySelector('.container');
    if (container) {
        container.insertBefore(alertDiv, container.firstChild);

        // Auto-hide after 5 seconds
        setTimeout(() => {
            alertDiv.style.display = 'none';
        }, 5000);
    }
}

/**
 * Disable/enable form based on event status
 */
function updateEventButton(eventId, status) {
    const button = document.querySelector(`button[onclick="registerEvent(${eventId})"]`);

    if (button && status === 'Full') {
        button.disabled = true;
        button.textContent = 'Event Full';
        button.className = 'btn btn-outline-secondary btn-sm';
    }
}

/**
 * Calculate days until event
 * @param {String} eventDate - ISO date string
 * @returns {Number} Days until event
 */
function daysUntilEvent(eventDate) {
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const event = new Date(eventDate);
    event.setHours(0, 0, 0, 0);

    const diff = event - today;
    return Math.ceil(diff / (1000 * 60 * 60 * 24));
}

/**
 * Format registration count display
 * @param {Number} registered - Current registrations
 * @param {Number} required - Required volunteers
 * @returns {String} Formatted string
 */
function formatRegistrationCount(registered, required) {
    const percentage = Math.round((registered / required) * 100);
    return `${registered}/${required} (${percentage}%)`;
}

/**
 * Validate phone number format
 * @param {String} phone - Phone number
 * @returns {Boolean} True if valid
 */
function validatePhone(phone) {
    const re = /^[\d\s\-\+\(\)]{10,}$/;
    return re.test(phone);
}

/**
 * Validate password strength
 * @param {String} password - Password to validate
 * @returns {Object} {isValid: boolean, message: string}
 */
function validatePasswordStrength(password) {
    if (password.length < 6) {
        return { isValid: false, message: 'Password must be at least 6 characters' };
    }
    if (!/[A-Z]/.test(password)) {
        return { isValid: false, message: 'Password must contain an uppercase letter' };
    }
    if (!/[0-9]/.test(password)) {
        return { isValid: false, message: 'Password must contain a number' };
    }
    return { isValid: true, message: 'Password is strong' };
}

/**
 * Clear form fields
 * @param {HTMLFormElement} form - Form to clear
 */
function clearForm(form) {
    if (form) {
        form.reset();
    }
}

/**
 * Toggle password visibility
 */
function togglePasswordVisibility(inputId) {
    const input = document.getElementById(inputId);
    if (input) {
        input.type = input.type === 'password' ? 'text' : 'password';
    }
}

/**
 * Confirm action before proceeding
 * @param {String} message - Confirmation message
 * @returns {Boolean} User's confirmation
 */
function confirmAction(message) {
    return confirm(message || 'Are you sure you want to continue?');
}

/**
 * Format volunteer status badge
 * @param {Number} registered - Current registrations
 * @param {Number} required - Required volunteers
 * @returns {String} Status ('Open', 'Full')
 */
function getEventStatus(registered, required) {
    return registered >= required ? 'Full' : 'Open';
}

/**
 * Update progress bar width
 * @param {String} progressBarSelector - CSS selector for progress bar
 * @param {Number} current - Current value
 * @param {Number} total - Total value
 */
function updateProgressBar(progressBarSelector, current, total) {
    const progressBar = document.querySelector(progressBarSelector);
    if (progressBar) {
        const percentage = Math.min((current / total) * 100, 100);
        progressBar.style.width = `${percentage}%`;
    }
}

/**
 * Disable all buttons in a form
 * @param {HTMLFormElement} form - Form to disable
 */
function disableFormButtons(form) {
    if (form) {
        const buttons = form.querySelectorAll('button');
        buttons.forEach(btn => {
            btn.disabled = true;
            btn.style.opacity = '0.6';
            btn.style.cursor = 'not-allowed';
        });
    }
}

/**
 * Enable all buttons in a form
 * @param {HTMLFormElement} form - Form to enable
 */
function enableFormButtons(form) {
    if (form) {
        const buttons = form.querySelectorAll('button');
        buttons.forEach(btn => {
            btn.disabled = false;
            btn.style.opacity = '1';
            btn.style.cursor = 'pointer';
        });
    }
}

/**
 * Check if user is on mobile device
 * @returns {Boolean} True if mobile
 */
function isMobileDevice() {
    return /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
}

/**
 * Scroll to element smoothly
 * @param {HTMLElement} element - Element to scroll to
 */
function scrollToElement(element) {
    if (element) {
        element.scrollIntoView({ behavior: 'smooth' });
    }
}
