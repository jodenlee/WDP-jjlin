/**
 * CORE INTERFACE LOGIC: Handles general UI enhancements, greetings, and mobile navigation
 */
document.addEventListener('DOMContentLoaded', () => {
    // INITIALIZE UI: Setup greeting and general listeners
    console.log("GenerationsConnect dashboard loaded.");

    // GREETING LOGIC: Generate a time-based greeting for the hero section
    const hours = new Date().getHours();
    let greeting = "Welcome";
    if (hours < 12) greeting = "Good Morning";
    else if (hours < 18) greeting = "Good Afternoon";
    else greeting = "Good Evening";

    // HERO SECTION UPDATE: Update the main title with the personalized greeting
    const heroTitle = document.querySelector('.hero h1');
    if (heroTitle) {
        heroTitle.innerText = greeting + heroTitle.innerText;
    }

    // MOBILE NAVIGATION TOGGLE: Handles the hamburger menu for small screens
    const hamburger = document.querySelector('.hamburger');
    const navLinks = document.querySelector('.nav-links');

    if (hamburger) {
        hamburger.addEventListener('click', () => {
            navLinks.classList.toggle('active');
        });
    }

    // Theme Handling
    const savedTheme = localStorage.getItem('theme') || 'light';
    applyTheme(savedTheme);

    // If on profile page, set the radio button
    const themeRadio = document.querySelector(`input[name="theme"][value="${savedTheme}"]`);
    if (themeRadio) themeRadio.checked = true;

    // Theme Change Listener
    const themeRadios = document.querySelectorAll('input[name="theme"]');
    themeRadios.forEach(radio => {
        radio.addEventListener('change', (e) => {
            if (e.target.checked) {
                // Map the ID to the theme name
                let theme = 'light';
                if (e.target.id === 'theme_dark') theme = 'dark';
                if (e.target.id === 'theme_auto') theme = 'auto'; // Future support
                setTheme(theme);
            }
        });
    });

    // GLOBAL MODAL VALIDATION: Intercepts specific flash messages to show a success modal
    checkAlertsForModals();
});


function setTheme(theme) {
    localStorage.setItem('theme', theme);
    applyTheme(theme);
}

function applyTheme(theme) {
    // We strictly want the 'boxes' (components) to stay light, so we force data-bs-theme to light
    document.documentElement.setAttribute('data-bs-theme', 'light');

    // We toggle the custom class on body to change the background color
    if (theme === 'dark') {
        document.body.classList.add('dark-theme');
    } else {
        document.body.classList.remove('dark-theme');
    }
}

// Toggle password visibility
function togglePassword(inputId, button) {
    const input = document.getElementById(inputId);
    const icon = button.querySelector('i');

    if (input.type === 'password') {
        input.type = 'text';
        icon.classList.remove('fa-eye');
        icon.classList.add('fa-eye-slash');
    } else {
        input.type = 'password';
        icon.classList.remove('fa-eye-slash');
        icon.classList.add('fa-eye');
    }
}
/**
 * Checks for specific alert messages and converts them into a global success modal.
 * This provides a more polished user experience for key actions like reporting or logging in.
 */
function checkAlertsForModals() {
    // List of triggers that should convert an alert into a modal
    const modalTriggers = [
        {
            keywords: ['Story created successfully!', 'Story updated successfully!', 'Group created successfully!', 'Group post created successfully!', 'Post created successfully!', 'Comment posted successfully!', 'Reply posted successfully!'],
            title: 'Content Posted!',
            body: 'Your content has been successfully shared with the community.'
        },
        {
            keywords: ['Story updated successfully!', 'Group updated successfully!', 'Post updated successfully!', 'Comment updated successfully!', 'Reply updated successfully!'],
            title: 'Updated!',
            body: 'Your changes have been successfully saved.'
        },
        {
            keywords: ['Story reported', 'Group reported', 'Comment reported'],
            title: 'Report Submitted',
            body: 'Thank you for helping keep our community safe.'
        },
        {
            keywords: ['already reported this story', 'already reported this group', 'already reported this comment'],
            title: 'Already Reported',
            body: 'You have already reported this item. We are reviewing it.',
            btnClass: 'btn-primary'
        },
        {
            keywords: ['Welcome back!'],
            title: 'Login Successful',
            body: 'Welcome back to TogetherSG!',
            btnClass: 'btn-primary'
        },
        {
            keywords: ['Account created successfully!'],
            title: 'Welcome to TogetherSG!',
            body: 'Your account has been created successfully. Please log in to continue.',
            btnClass: 'btn-primary'
        },
        {
            keywords: ['You have been logged out.'],
            title: 'Logged Out',
            body: 'You have been successfully logged out. See you again soon!',
            btnClass: 'btn-primary'
        },
        {
            keywords: ['Comment posted successfully!'],
            title: 'Comment Posted',
            body: 'Your comment has been added to the story.',
            btnClass: 'btn-primary'
        },
        {
            keywords: ['Comment deleted.'],
            title: 'Comment Deleted',
            body: 'Your comment has been successfully removed.',
            btnClass: 'btn-primary'
        },
        {
            keywords: ['Story deleted successfully.'],
            title: 'Story Deleted',
            body: 'Your story has been permanently removed.',
            btnClass: 'btn-primary'
        },
        {
            keywords: ['Reply deleted.'],
            title: 'Reply Deleted',
            body: 'Your reply has been successfully removed.',
            btnClass: 'btn-primary'
        },
        {
            keywords: ['flagged by our safety system'],
            title: 'Safety Warning',
            body: 'Your content has been flagged by our safety system. Please ensure it follows community guidelines.',
            btnClass: 'btn-danger'
        }
    ];

    // Select all alerts (success, info, and warning)
    const alerts = document.querySelectorAll('.alert-success, .alert-info, .alert-warning');

    alerts.forEach(function (alert) {
        const text = alert.textContent.trim();
        let matched = false;

        for (const trigger of modalTriggers) {
            // Check if any keyword matches
            const match = trigger.keywords.some(keyword => text.includes(keyword));

            if (match) {
                // Hide the original alert
                alert.classList.remove('show');
                alert.classList.add('d-none');

                // Update Modal Content
                const modalTitle = document.getElementById('globalSuccessModalLabel');
                const modalBody = document.getElementById('globalSuccessModalBody');

                if (modalTitle && modalBody) {
                    modalTitle.textContent = trigger.title;
                    modalBody.textContent = trigger.body;

                    // Update Button Theme
                    const modalBtn = document.getElementById('globalSuccessModalBtn');
                    if (modalBtn) {
                        modalBtn.className = 'btn px-5 fw-bold ' + (trigger.btnClass || 'btn-primary');
                    }

                    // Show the modal
                    var myModal = new bootstrap.Modal(document.getElementById('globalSuccessModal'));
                    myModal.show();
                }
                matched = true;
                break; // Stop after first match
            }
        }
    });
}

/**
 * Global helper to trigger the success/warning modal programmatically.
 * Useful for AJAX responses.
 */
window.showGlobalModal = function (title, body, btnClass = 'btn-primary') {
    const modalTitle = document.getElementById('globalSuccessModalLabel');
    const modalBody = document.getElementById('globalSuccessModalBody');
    const modalBtn = document.getElementById('globalSuccessModalBtn');

    if (modalTitle && modalBody) {
        modalTitle.textContent = title;
        modalBody.textContent = body;

        if (modalBtn) {
            modalBtn.className = 'btn px-5 fw-bold ' + btnClass;
        }

        const modalEl = document.getElementById('globalSuccessModal');
        if (modalEl) {
            const myModal = new bootstrap.Modal(modalEl);
            myModal.show();
        }
    }
};



// ============================================================================
// REAL-TIME NOTIFICATIONS
// ============================================================================
let notificationPollingInterval = null;

function startNotificationPolling() {
    // Only poll if user is logged in (check if notification bell exists)
    const notifDropdown = document.getElementById('notificationsDropdown');
    if (!notifDropdown) return;

    // Poll immediately, then every 30 seconds
    fetchNotifications();
    notificationPollingInterval = setInterval(fetchNotifications, 30000);
}

function fetchNotifications() {
    fetch('/api/notifications')
        .then(response => {
            if (!response.ok) throw new Error('Not logged in');
            return response.json();
        })
        .then(data => {
            updateNotificationUI(data);
        })
        .catch(err => {
            // User not logged in or error - stop polling
            if (notificationPollingInterval) {
                clearInterval(notificationPollingInterval);
            }
        });
}

function updateNotificationUI(data) {
    // Update badge count
    const badge = document.getElementById('notification-badge');
    if (badge) {
        if (data.unread_count > 0) {
            badge.textContent = data.unread_count;
            badge.style.display = 'block';
        } else {
            badge.style.display = 'none';
        }
    }

    // Update dropdown content
    const notificationsItems = document.getElementById('notifications-items');
    if (!notificationsItems) return;

    if (data.notifications.length > 0) {
        let html = '';
        data.notifications.forEach(notif => {
            html += `
                <li>
                    <div class="dropdown-item p-3 border-bottom whitespace-normal" style="white-space: normal;">
                        <div class="d-flex justify-content-between align-items-start mb-2">
                            <span class="badge bg-light text-primary border" style="font-size: 0.85rem;">${notif.type}</span>
                            <small class="text-muted" style="font-size: 0.85rem;">${notif.created_at}</small>
                        </div>
                        <p class="mb-3 fw-semibold text-dark fs-6">${notif.content}</p>
                        <div class="d-flex justify-content-end gap-3 mt-1">
                            ${notif.link ? `<a href="${notif.link}" class="btn btn-sm btn-outline-primary py-1 px-3" style="font-size: 0.85rem;">View</a>` : ''}
                            <button onclick="markAsRead(${notif.id}, this)" class="btn btn-sm btn-link p-0 text-muted text-decoration-none" style="font-size: 0.85rem;">Dismiss</button>
                        </div>
                    </div>
                </li>
            `;
        });
        notificationsItems.innerHTML = html;
    } else {
        notificationsItems.innerHTML = `
            <li class="p-4 text-center text-muted">
                <i class="fas fa-bell-slash mb-2 d-block fa-2x"></i>
                <span class="small">No new notifications</span>
            </li>
        `;
    }
}

function markAsRead(id, btn) {
    fetch(`/notifications/mark_read/${id}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    })
        .then(response => {
            if (response.ok) {
                // Re-fetch to update UI
                fetchNotifications();
            }
        })
        .catch(err => console.error('Error marking as read:', err));
}

// Start polling when page loads
document.addEventListener('DOMContentLoaded', () => {
    startNotificationPolling();
});