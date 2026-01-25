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
});
