from flask import Blueprint, redirect, request, session, jsonify
from utils import get_db, login_required, get_conn, auto_translate
from datetime import datetime, timedelta, timezone

notifications_bp = Blueprint('notifications', __name__)

SGT = timezone(timedelta(hours=8))

# ============================================================================
# NOTIFICATION ROUTES
# ============================================================================

@notifications_bp.route('/notifications/mark_read/<int:notif_id>', methods=['POST'])
@login_required
def mark_notification_read(notif_id):
    """Mark a single notification as read"""
    db = get_db()
    conn = get_conn()
    conn.execute("UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?", (notif_id, session['user_id']))
    conn.commit()
    return "OK", 200

@notifications_bp.route('/notifications/delete/<int:notif_id>', methods=['POST'])
@login_required
def delete_notification(notif_id):
    """Delete a single notification"""
    db = get_db()
    conn = get_conn()
    conn.execute("DELETE FROM notifications WHERE id = ? AND user_id = ?", (notif_id, session['user_id']))
    conn.commit()
    return "OK", 200

@notifications_bp.route('/notifications/clear_all', methods=['POST'])
@login_required
def clear_all_notifications():
    """Mark all notifications as read"""
    db = get_db()
    conn = get_conn()
    conn.execute("UPDATE notifications SET is_read = 1 WHERE user_id = ?", (session['user_id'],))
    conn.commit()
    return redirect(request.referrer)

@notifications_bp.route('/api/notifications')
@login_required
def api_notifications():
    """API endpoint for real-time notification polling"""
    db = get_db()
    notifications = db.query(
        """SELECT id, type, content, link, created_at 
           FROM notifications 
           WHERE user_id = ? AND is_read = 0 
           ORDER BY created_at DESC 
           LIMIT 10""", 
        (session['user_id'],)
    )
    
    # Convert to list of dicts for JSON serialization
    notif_list = []
    for n in notifications:
        # Translate notification content
        translated_content = auto_translate(n['content'])
        
        # Timestamps are already stored in SGT – just display as-is
        display_time = str(n['created_at'])[:16] if n['created_at'] else ''
        
        notif_list.append({
            'id': n['id'],
            'type': n['type'],
            'content': translated_content,
            'link': n['link'],
            'created_at': display_time
        })
    
    return jsonify({
        'notifications': notif_list,
        'unread_count': len(notifications)
    })
