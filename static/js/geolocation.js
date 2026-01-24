/**
 * Geolocation Utilities for TogetherSG
 * Uses Browser Geolocation API and Google Geocoding API
 */

// API key is injected via the base template
const GOOGLE_MAPS_API_KEY = window.GOOGLE_MAPS_API_KEY || '';

// Known Singapore locations (from partials/locations.html)
const SINGAPORE_LOCATIONS = [
    "Marina Bay Sands", "Gardens by the Bay", "Sentosa", "Orchard Road",
    "Chinatown", "Little India", "Clarke Quay", "Boat Quay",
    "Bugis", "Kampong Glam", "Tiong Bahru", "Toa Payoh",
    "Jurong East", "Tampines", "Bedok", "Ang Mo Kio",
    "Yishun", "Woodlands", "Punggol", "Sengkang",
    "Bishan", "Clementi", "Bukit Timah", "Holland Village",
    "Dempsey Hill", "East Coast Park", "Changi", "Pasir Ris",
    "Serangoon", "Hougang", "Maxwell Food Centre", "Lau Pa Sat",
    "Newton Food Centre", "Old Airport Road", "Adam Road Food Centre"
];

/**
 * Gets the user's current location using the browser's Geolocation API.
 * @returns {Promise<{lat: number, lng: number}>}
 */
function getCurrentLocation() {
    return new Promise((resolve, reject) => {
        if (!navigator.geolocation) {
            reject(new Error('Geolocation is not supported by your browser.'));
            return;
        }
        navigator.geolocation.getCurrentPosition(
            (position) => {
                resolve({
                    lat: position.coords.latitude,
                    lng: position.coords.longitude
                });
            },
            (error) => {
                let message = 'Could not get your location.';
                if (error.code === error.PERMISSION_DENIED) {
                    message = 'Location permission denied. Please enable it in your browser settings.';
                }
                reject(new Error(message));
            },
            { enableHighAccuracy: true, timeout: 10000 }
        );
    });
}

/**
 * Reverse geocodes coordinates to a human-readable address using Google Geocoding API.
 * @param {number} lat
 * @param {number} lng
 * @returns {Promise<string>} The formatted address or locality.
 */
async function reverseGeocode(lat, lng) {
    // Debug: Check if API key is available
    if (!GOOGLE_MAPS_API_KEY) {
        console.error('GOOGLE_MAPS_API_KEY is not set!');
        throw new Error('Google Maps API key is not configured. Please check your setup.');
    }

    const url = `https://maps.googleapis.com/maps/api/geocode/json?latlng=${lat},${lng}&key=${GOOGLE_MAPS_API_KEY}`;
    const response = await fetch(url);
    const data = await response.json();

    // Debug: Log the full response
    console.log('Geocoding API response:', data);

    if (data.status !== 'OK' || !data.results.length) {
        // Provide more specific error messages based on API response
        const errorMessages = {
            'REQUEST_DENIED': 'API key is invalid or Geocoding API is not enabled in Google Cloud Console.',
            'OVER_QUERY_LIMIT': 'API quota exceeded. Please check your Google Cloud billing.',
            'ZERO_RESULTS': 'No address found for this location.',
            'INVALID_REQUEST': 'Invalid coordinates provided.'
        };
        const msg = errorMessages[data.status] || `Geocoding failed: ${data.status}`;
        console.error('Geocoding error:', data.status, data.error_message || '');
        throw new Error(msg);
    }

    // Extract locality or sublocality from address components
    const result = data.results[0];
    let locality = '';
    for (const component of result.address_components) {
        if (component.types.includes('sublocality_level_1') || component.types.includes('locality') || component.types.includes('neighborhood')) {
            locality = component.long_name;
            break;
        }
    }

    return locality || result.formatted_address;
}

/**
 * Matches a geocoded address to the closest known Singapore location.
 * @param {string} address
 * @returns {string} The best matching known location, or the original address.
 */
function categorizeToSingaporeLocation(address) {
    const lowerAddress = address.toLowerCase();
    for (const loc of SINGAPORE_LOCATIONS) {
        if (lowerAddress.includes(loc.toLowerCase())) {
            return loc;
        }
    }
    // If no exact match, return the geocoded locality as is
    return address;
}

/**
 * Main function to populate a location input field with the user's current location.
 * @param {string} inputId - The ID of the input element to populate.
 * @param {string} [buttonId] - Optional ID of the button to show a loading state.
 */
async function populateLocationField(inputId, buttonId) {
    const inputElement = document.getElementById(inputId);
    const buttonElement = buttonId ? document.getElementById(buttonId) : null;

    if (!inputElement) {
        console.error('Location input not found:', inputId);
        return;
    }

    const originalButtonText = buttonElement ? buttonElement.innerHTML : '';
    try {
        if (buttonElement) {
            buttonElement.disabled = true;
            buttonElement.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Locating...';
        }

        const coords = await getCurrentLocation();
        const address = await reverseGeocode(coords.lat, coords.lng);
        const finalLocation = categorizeToSingaporeLocation(address);
        inputElement.value = finalLocation;

    } catch (error) {
        alert(error.message);
    } finally {
        if (buttonElement) {
            buttonElement.disabled = false;
            buttonElement.innerHTML = originalButtonText;
        }
    }
}
