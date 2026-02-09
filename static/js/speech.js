/**
 * SPEECH RECOGNITION HELPER
 * Uses the Web Speech API to transcribe voice to text.
 */

function toggleSpeechRecognition(buttonId, targetInputId, langSelectorId) {
    const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;

    if (!SpeechRecognition) {
        alert("Your browser does not support Speech Recognition. Please use Chrome or Edge.");
        return;
    }

    const button = document.getElementById(buttonId);
    const targetInput = document.getElementById(targetInputId);
    const langSelector = document.getElementById(langSelectorId);
    const icon = button.querySelector('i');

    // Create recognition instance if it doesn't exist on the button
    if (!button.recognition) {
        button.recognition = new SpeechRecognition();
        button.recognition.continuous = true;
        button.recognition.interimResults = true;

        button.recognition.onstart = () => {
            button.classList.add('btn-danger', 'listening-pulse');
            button.classList.remove('btn-outline-secondary');
            if (icon) {
                icon.classList.remove('fa-microphone');
                icon.classList.add('fa-stop');
            }
        };

        button.recognition.onresult = (event) => {
            let finalTranscript = '';
            for (let i = event.resultIndex; i < event.results.length; ++i) {
                if (event.results[i].isFinal) {
                    finalTranscript += event.results[i][0].transcript;
                }
            }
            if (finalTranscript) {
                // Append space if there's already content
                const currentVal = targetInput.value.trim();
                targetInput.value = currentVal ? currentVal + ' ' + finalTranscript : finalTranscript;
                // Trigger input event for any auto-expanding textareas
                targetInput.dispatchEvent(new Event('input'));
            }
        };

        button.recognition.onerror = (event) => {
            console.error("Speech recognition error:", event.error);
            stopRecognition(button, icon);
        };

        button.recognition.onend = () => {
            stopRecognition(button, icon);
        };
    }

    // Toggle logic
    if (button.classList.contains('listening-pulse')) {
        button.recognition.stop();
    } else {
        // Set language before starting
        button.recognition.lang = langSelector ? langSelector.value : 'en-SG';
        button.recognition.start();
    }
}

/**
 * Clears the target input or textarea and triggers an input event.
 */
function clearInput(inputId) {
    const input = document.getElementById(inputId);
    if (input) {
        input.value = '';
        input.focus();
        // Trigger input event for validation or auto-expanding textareas
        input.dispatchEvent(new Event('input'));
    }
}

function stopRecognition(button, icon) {
    button.classList.remove('btn-danger', 'listening-pulse');
    button.classList.add('btn-outline-secondary');
    if (icon) {
        icon.classList.remove('fa-stop');
        icon.classList.add('fa-microphone');
    }
}
