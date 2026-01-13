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
});
