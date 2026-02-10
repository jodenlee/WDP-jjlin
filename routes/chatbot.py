from flask import Blueprint, request, jsonify, session
from datetime import datetime
import re

chatbot_bp = Blueprint('chatbot', __name__)

_chatbot_rate = {}  # { session_id: [timestamp, ...] }

@chatbot_bp.route('/api/chatbot', methods=['POST'])
def api_chatbot():
    """
    Accepts { "message": "user text" }
    Returns  { "reply":  "bot response" }
    """
    # --- Rate limiting: max 10 requests per minute per session ---
    sid = session.get('user_id', request.remote_addr)
    now = datetime.now()
    window = _chatbot_rate.setdefault(sid, [])
    # Remove entries older than 60 seconds
    window[:] = [t for t in window if (now - t).total_seconds() < 60]
    if len(window) >= 10:
        return jsonify({'reply': 'You are sending messages too quickly. Please wait a moment and try again.'}), 429
    window.append(now)

    data = request.get_json(silent=True) or {}
    user_msg = (data.get('message') or '').strip()

    if not user_msg:
        return jsonify({'reply': 'Please type a question and I will do my best to help!'}), 200
    if len(user_msg) > 500:
        return jsonify({'reply': 'Your message is too long. Please keep it under 500 characters.'}), 200

    reply = _chatbot_get_reply(user_msg)
    return jsonify({'reply': reply}), 200


def _chatbot_get_reply(msg):
    """Match keywords in the user message and return a helpful response."""
    m = msg.lower()

    # --- Home / Dashboard ---
    if any(w in m for w in ['home', 'dashboard', 'main page', 'landing']):
        return (
            "The Home page is your starting point! From here you can:\n"
            "1. Jump to Stories, Community, Activities, Messages, or Profile.\n"
            "2. See the newest stories and upcoming events at a glance.\n"
            "Just click any card to explore that section."
        )

    # --- Messages / Chat ---
    if any(w in m for w in ['message', 'chat', 'inbox', 'conversation', 'dm', 'direct']):
        if any(w in m for w in ['archive', 'archived']):
            return (
                "To view archived chats:\n"
                "1. Go to Messages.\n"
                "2. Look for the 'Archived' section at the top.\n"
                "3. Click it to see all chats you have archived.\n"
                "You can unarchive a chat by long-pressing or using the menu."
            )
        if any(w in m for w in ['unread', 'new message', 'notification']):
            return (
                "Unread messages show a coloured badge next to the chat.\n"
                "To mark all as read, open Messages and look for the '...' menu, "
                "then select 'Read all'. You can also open each chat to mark it read."
            )
        if any(w in m for w in ['start', 'new', 'begin', 'create', 'how to']):
            return (
                "To start a new chat:\n"
                "1. Go to the Messages page.\n"
                "2. Click the '+' button at the top.\n"
                "3. Choose 'New contact' to send a direct message, "
                "or 'New group' to create a group chat.\n"
                "4. Select a user and start typing!"
            )
        if any(w in m for w in ['group', 'group chat']):
            return (
                "Group chats let you talk with multiple people at once.\n"
                "To create one: Messages → '+' → 'New group' → add members → set a name → create!\n"
                "You can share text, images, voice messages, and even your live location."
            )
        if any(w in m for w in ['delete', 'remove']):
            return (
                "To delete a message:\n"
                "1. Long-press (or right-click) the message.\n"
                "2. Select 'Delete' from the menu.\n"
                "3. Note: Deleting removes the message for everyone in the chat."
            )
        if any(w in m for w in ['edit', 'change', 'modify']):
            return (
                "To edit a message you sent:\n"
                "1. Long-press (or right-click) your message.\n"
                "2. Select 'Edit' from the context menu.\n"
                "3. Make your changes and press Enter to save.\n"
                "The other person will see the updated version."
            )
        # General messages help
        return (
            "The Messages page is where all your chats live.\n"
            "You can:\n"
            "• Send text, images, voice messages, and locations.\n"
            "• Pin, mute, archive, or delete chats.\n"
            "• Start a new chat with the '+' button.\n"
            "What specifically would you like help with?"
        )

    # --- FAQ / Help ---
    if any(w in m for w in ['faq', 'help', 'question', 'support']):
        return (
            "You can find answers to common questions on the FAQ & Help page.\n"
            "Topics include: Accounts & Access, Messages & Chat, Editing & Deleting, "
            "Stories, Groups, and Activities.\n"
            "Just click any question to expand the answer!"
        )

    # --- Stories ---
    if 'stor' in m:
        return (
            "Stories are public posts shared with the community.\n"
            "To read: go to Stories and click any title.\n"
            "To write: click 'Create Story', add a title and content, then publish.\n"
            "You can also like, comment on, and bookmark stories."
        )

    # --- Groups / Community ---
    if any(w in m for w in ['group', 'community', 'communities']):
        return (
            "Groups are communities of people with shared interests.\n"
            "To join one: go to Groups → browse → click 'Join'.\n"
            "To create one: Groups → 'Create Group' → fill in the details.\n"
            "Each group has its own chat where members can talk."
        )

    # --- Activities / Events ---
    if any(w in m for w in ['activit', 'event', 'workshop']):
        return (
            "Activities are events or workshops you can join.\n"
            "Go to Activities to see what's coming up.\n"
            "Click an activity for details, then hit 'Join' to sign up.\n"
            "You can also create your own activity!"
        )

    # --- Profile / Account ---
    if any(w in m for w in ['profile', 'account', 'settings', 'password', 'name']):
        return (
            "To manage your account: click your avatar in the top-right → Settings.\n"
            "From there you can update your name, bio, and profile picture.\n"
            "If you forgot your password, try the login page or ask an admin for help."
        )

    # --- Greetings ---
    if any(w in m for w in ['hello', 'hi', 'hey', 'good morning', 'good afternoon']):
        return "Hello! 👋 I'm the TogetherSG helper. How can I help you today?"

    if any(w in m for w in ['thanks', 'thank you', 'thx', 'cheers']):
        return "You're welcome! Let me know if there's anything else I can help with. 😊"

    if any(w in m for w in ['bye', 'goodbye', 'see you']):
        return "Goodbye! Have a great day! Feel free to chat anytime you need help. 👋"

    # --- Fallback ---
    return (
        "I'm not sure I understand. Could you try asking in a different way?\n"
        "I can help with:\n"
        "• Home / Dashboard\n"
        "• Messages & Chats\n"
        "• Stories, Groups, Activities\n"
        "• FAQ & Help\n"
        "• Profile & Account"
    )
