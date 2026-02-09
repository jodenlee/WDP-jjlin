document.addEventListener('DOMContentLoaded', () => {
    console.log("GenerationsConnect dashboard loaded.");

    // Simple interaction to greet user (simulating personalization)
    const hours = new Date().getHours();
    let greeting = "Welcome";
    if (hours < 12) greeting = "Good Morning";
    else if (hours < 18) greeting = "Good Afternoon";
    else greeting = "Good Evening";

    // You could inject this greeting into the DOM if an element existed, 
    // for now we just log it or we could update the hero title.
    const heroTitle = document.querySelector('.hero h1');
    if (heroTitle) {
        heroTitle.innerText = `${greeting}! ` + heroTitle.innerText;
    }

    // Toggle Navbar
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

// ============================================================================
// REAL-TIME NOTIFICATIONS
// ============================================================================
let notificationPollingInterval = null;

function startNotificationPolling() {
    // Only poll if user is logged in (check if notification bell exists)
    const notifDropdown = document.getElementById('notifDropdown');
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
    const badge = document.querySelector('#notifDropdown .badge');
    const existingBadge = badge;

    if (data.unread_count > 0) {
        if (existingBadge) {
            existingBadge.textContent = data.unread_count;
        } else {
            // Create badge if it doesn't exist
            const notifIcon = document.querySelector('#notifDropdown');
            if (notifIcon) {
                const newBadge = document.createElement('span');
                newBadge.className = 'position-absolute top-0 start-100 translate-middle badge rounded-pill bg-danger';
                newBadge.style.fontSize = '0.5rem';
                newBadge.textContent = data.unread_count;
                notifIcon.appendChild(newBadge);
            }
        }
    } else {
        if (existingBadge) {
            existingBadge.remove();
        }
    }

    // Update dropdown content
    const dropdownMenu = document.querySelector('#notifDropdown + .dropdown-menu');
    if (!dropdownMenu) return;

    // Keep the header and clear all button, update the content
    let html = '<li><h6 class="dropdown-header fw-bold border-bottom">Notifications</h6></li>';

    if (data.notifications.length > 0) {
        data.notifications.forEach(notif => {
            html += `
                <li>
                    <div class="dropdown-item p-2 border-bottom">
                        <div class="d-flex justify-content-between">
                            <small class="fw-bold text-primary">${notif.type}</small>
                            <small class="text-muted">${notif.created_at}</small>
                        </div>
                        <p class="mb-1 text-wrap small">${notif.content}</p>
                        <div class="d-flex justify-content-end gap-2">
                            ${notif.link ? `<a href="${notif.link}" class="btn btn-link p-0 text-decoration-none small">View</a>` : ''}
                            <form action="/notifications/mark_read/${notif.id}" method="POST" class="d-inline">
                                <button type="submit" class="btn btn-link p-0 text-muted text-decoration-none small">Dismiss</button>
                            </form>
                        </div>
                    </div>
                </li>
            `;
        });
        html += `
            <li class="p-2 text-center">
                <form action="/notifications/clear_all" method="POST">
                    <button type="submit" class="btn btn-light btn-sm w-100">Clear All</button>
                </form>
            </li>
        `;
    } else {
        html += '<li class="p-3 text-center text-muted small">No new notifications</li>';
    }

    dropdownMenu.innerHTML = html;
}

// Start polling when page loads
document.addEventListener('DOMContentLoaded', () => {
    startNotificationPolling();
});
