from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from utils import get_db, login_required, create_notification, get_conn

messages_bp = Blueprint('messages', __name__)

@messages_bp.route('/messages')
@login_required
def messages_list():
    db = get_db()
    user_id = session['user_id']
    
    # Get all users for starting new conversations
    users = db.query("SELECT * FROM users WHERE id != ?", (user_id,))
    
    # Get conversations (users we've messaged with)
    conversations = db.query("""
        SELECT DISTINCT 
            CASE WHEN sender_id = ? THEN receiver_id ELSE sender_id END as user_id,
            u.username,
            (SELECT content FROM messages m2 
             WHERE (m2.sender_id = u.id AND m2.receiver_id = ?) 
                OR (m2.sender_id = ? AND m2.receiver_id = u.id)
             ORDER BY m2.created_at DESC LIMIT 1) as last_message,
            (SELECT created_at FROM messages m3 
             WHERE (m3.sender_id = u.id AND m3.receiver_id = ?) 
                OR (m3.sender_id = ? AND m3.receiver_id = u.id)
             ORDER BY m3.created_at DESC LIMIT 1) as last_message_time,
            (SELECT COUNT(*) FROM messages m4 
             WHERE m4.sender_id = u.id AND m4.receiver_id = ? AND m4.is_read = 0) as unread_count
        FROM messages m
        JOIN users u ON u.id = CASE WHEN m.sender_id = ? THEN m.receiver_id ELSE m.sender_id END
        WHERE m.sender_id = ? OR m.receiver_id = ?
        ORDER BY last_message_time DESC
    """, (user_id, user_id, user_id, user_id, user_id, user_id, user_id, user_id, user_id))
    
    return render_template('messages/index.html', conversations=conversations, users=users)

@messages_bp.route('/messages/<int:user_id>')
@login_required
def chat(user_id):
    db = get_db()
    current_user_id = session['user_id']
    
    other_user = db.query("SELECT * FROM users WHERE id = ?", (user_id,), one=True)
    if not other_user:
        return "User not found", 404
    
    # Get messages between users
    messages_data = db.query("""
        SELECT * FROM messages 
        WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
        ORDER BY created_at ASC
    """, (current_user_id, user_id, user_id, current_user_id))
    
    # Mark messages as read
    conn = get_conn()
    conn.execute("UPDATE messages SET is_read = 1 WHERE sender_id = ? AND receiver_id = ?", (user_id, current_user_id))
    conn.commit()
    
    return render_template('messages/chat.html', messages=messages_data, other_user=other_user, current_user_id=current_user_id)

@messages_bp.route('/messages/send/<int:recipient_id>', methods=['POST'])
@login_required
def send_message(recipient_id):
    content = request.form['content']
    sender_id = session['user_id']
    
    db = get_db()
    conn = get_conn()
    conn.execute(
        "INSERT INTO messages (sender_id, receiver_id, content) VALUES (?, ?, ?)",
        (sender_id, recipient_id, content)
    )
    conn.commit()
    
    # Notify Recipient
    sender = db.query("SELECT username FROM users WHERE id = ?", (sender_id,), one=True)
    create_notification(
        recipient_id, 
        'Message', 
        f"New message from {sender['username']}", 
        url_for('messages.chat', user_id=sender_id)
    )
    
    flash('Message sent!', 'success')
    return redirect(url_for('messages.chat', user_id=recipient_id))
