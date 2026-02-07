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
        heroTitle.innerText = `${greeting}! ` + heroTitle.innerText;
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
            keywords: ['Story created successfully!', 'Story updated successfully!'],
            title: 'Story Posted!',
            body: 'Your story has been successfully shared with the community.'
        },
        {
            keywords: ['Story updated successfully!'], // Handle specific update text if needed differently
            title: 'Story Updated!',
            body: 'Your story has been successfully updated.'
        },
        {
            keywords: ['Story reported'],
            title: 'Report Submitted',
            body: 'Thank you for helping keep our community safe.'
        },
        {
            keywords: ['already reported this story'],
            title: 'Already Reported',
            body: 'You have already reported this story. We are reviewing it.'
        },
        {
            keywords: ['Welcome back!'],
            title: 'Login Successful',
            body: 'Welcome back to TogetherSG!'
        },
        {
            keywords: ['Account created successfully!'],
            title: 'Welcome to TogetherSG!',
            body: 'Your account has been created successfully. Please log in to continue.'
        },
        {
            keywords: ['You have been logged out.'],
            title: 'Logged Out',
            body: 'You have been successfully logged out. See you again soon!'
        },
        {
            keywords: ['Comment posted successfully!'],
            title: 'Comment Posted',
            body: 'Your comment has been added to the story.'
        },
        {
            keywords: ['Comment deleted.'],
            title: 'Comment Deleted',
            body: 'Your comment has been successfully removed.'
        }
    ];

    // Select all alerts (success and info)
    const alerts = document.querySelectorAll('.alert-success, .alert-info');

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
