/**
 * TogetherSG Chatbot Widget
 * --------------------------
 * Handles: toggle, send/receive, typing indicator, localStorage,
 * rate limiting, input validation, keyboard accessibility.
 */
(function () {
    'use strict';

    // --- DOM References ---
    const toggle = document.getElementById('chatbot-toggle');
    const panel = document.getElementById('chatbot-panel');
    const msgs = document.getElementById('chatbot-messages');
    const input = document.getElementById('chatbot-input');
    const sendBtn = document.getElementById('chatbot-send');
    const clearBtn = document.getElementById('chatbot-clear');
    const typing = document.getElementById('chatbot-typing');

    if (!toggle || !panel) return; // Widget not on this page

    // --- Constants ---
    const STORAGE_KEY = 'togethersg_chatbot_history';
    const MAX_MSG_LEN = 500;
    const RATE_LIMIT_MS = 1000; // 1 message per second (client-side)

    let lastSendTime = 0;

    // ------------------------------------------------------------------
    // Toggle open / close
    // ------------------------------------------------------------------
    toggle.addEventListener('click', () => {
        const isOpen = panel.classList.toggle('open');
        toggle.classList.toggle('active', isOpen);
        toggle.setAttribute('aria-expanded', isOpen);
        if (isOpen) {
            input.focus();
            scrollToBottom();
        }
    });

    // Close on Escape key
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && panel.classList.contains('open')) {
            panel.classList.remove('open');
            toggle.classList.remove('active');
            toggle.setAttribute('aria-expanded', 'false');
            toggle.focus();
        }
    });

    // ------------------------------------------------------------------
    // Send message
    // ------------------------------------------------------------------
    sendBtn.addEventListener('click', sendMessage);

    input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendMessage();
        }
    });

    // Auto-resize textarea
    input.addEventListener('input', () => {
        input.style.height = 'auto';
        input.style.height = Math.min(input.scrollHeight, 80) + 'px';
    });

    async function sendMessage() {
        const text = input.value.trim();

        // --- Validation ---
        if (!text) return;
        if (text.length > MAX_MSG_LEN) {
            appendError('Message is too long. Please keep it under ' + MAX_MSG_LEN + ' characters.');
            return;
        }

        // --- Client-side rate limit ---
        const now = Date.now();
        if (now - lastSendTime < RATE_LIMIT_MS) {
            appendError('Please wait a moment before sending another message.');
            return;
        }
        lastSendTime = now;

        // --- Display user message ---
        appendMsg(text, 'user');
        input.value = '';
        input.style.height = 'auto';
        sendBtn.disabled = true;

        // --- Show typing indicator ---
        showTyping(true);

        try {
            const res = await fetch('/api/chatbot', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: text })
            });

            showTyping(false);

            if (!res.ok) throw new Error('Server error');

            const data = await res.json();
            appendMsg(data.reply || "Sorry, I didn't understand that.", 'bot');
        } catch (err) {
            showTyping(false);
            appendMsg(
                "Oops! I'm having trouble connecting right now. Please try again in a moment, or check the FAQ page for common answers.",
                'bot'
            );
        }

        sendBtn.disabled = false;
        input.focus();
    }

    // ------------------------------------------------------------------
    // Clear chat
    // ------------------------------------------------------------------
    clearBtn.addEventListener('click', () => {
        // Keep only the welcome message
        msgs.innerHTML = '';
        addWelcome();
        saveHistory();
        input.focus();
    });

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------
    function appendMsg(text, role) {
        const div = document.createElement('div');
        div.className = 'chatbot-msg ' + role;
        div.setAttribute('role', 'log');
        div.textContent = text;
        msgs.appendChild(div);
        scrollToBottom();
        saveHistory();
    }

    function appendError(text) {
        const div = document.createElement('div');
        div.className = 'chatbot-error';
        div.textContent = text;
        msgs.appendChild(div);
        scrollToBottom();
        // Auto-remove after 3 seconds
        setTimeout(() => div.remove(), 3000);
    }

    function showTyping(visible) {
        typing.classList.toggle('visible', visible);
        if (visible) scrollToBottom();
    }

    function scrollToBottom() {
        requestAnimationFrame(() => {
            msgs.scrollTop = msgs.scrollHeight;
        });
    }

    function addWelcome() {
        const w = document.createElement('div');
        w.className = 'chatbot-welcome';
        w.textContent = "Hi! I'm the TogetherSG helper. Ask me about the dashboard, messages, chats, or FAQs!";
        msgs.appendChild(w);
    }

    // ------------------------------------------------------------------
    // localStorage persistence (session-based)
    // ------------------------------------------------------------------
    function saveHistory() {
        const items = [];
        msgs.querySelectorAll('.chatbot-msg').forEach(el => {
            items.push({
                role: el.classList.contains('user') ? 'user' : 'bot',
                text: el.textContent
            });
        });
        try {
            localStorage.setItem(STORAGE_KEY, JSON.stringify(items));
        } catch (e) { /* quota exceeded — ignore */ }
    }

    function loadHistory() {
        try {
            const data = JSON.parse(localStorage.getItem(STORAGE_KEY));
            if (data && data.length) {
                data.forEach(m => {
                    const div = document.createElement('div');
                    div.className = 'chatbot-msg ' + m.role;
                    div.setAttribute('role', 'log');
                    div.textContent = m.text;
                    msgs.appendChild(div);
                });
                scrollToBottom();
            } else {
                addWelcome();
            }
        } catch (e) {
            addWelcome();
        }
    }

    // --- Initialize ---
    loadHistory();
})();
