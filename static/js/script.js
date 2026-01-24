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
