from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify, current_app
from utils import get_db, login_required, create_notification, get_conn, get_current_user, allowed_file
from extensions import socketio
from flask_socketio import emit, join_room, leave_room
import os
import re
import uuid
import time
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename

messages_bp = Blueprint('messages', __name__)

# ===== SOCKET.IO EVENTS =====
@socketio.on('join')
def on_join(data):
    room = data.get('room')
    if room: join_room(room)

@socketio.on('leave')
def on_leave(data):
    room = data.get('room')
    if room: leave_room(room)

@socketio.on('location_update')
def handle_location_update(data):
    room = data.get('room')
    if room: emit('live_location_update', data, to=room, include_self=False)

@socketio.on('typing')
def handle_typing(data):
    room = data.get('room')
    if room:
        data['sender_id'] = session.get('user_id')
        emit('user_typing', data, to=room, include_self=False)

@socketio.on('stop_typing')
def handle_stop_typing(data):
    room = data.get('room')
    if room:
        data['sender_id'] = session.get('user_id')
        emit('user_stop_typing', data, to=room, include_self=False)

# ===== ROUTES =====

@messages_bp.route('/messages')
@login_required
def messages_list():
    db = get_db()
    user_id = session['user_id']
    users = db.query("SELECT * FROM users WHERE id != ?", (user_id,))
    
    private_chats = db.query("""
        SELECT u.id as user_id, COALESCE(n.nickname, u.username) as username, u.username as original_username, u.profile_pic, 'private' as type,
               (SELECT content FROM messages m2 WHERE ((m2.sender_id = u.id AND m2.receiver_id = ?) OR (m2.sender_id = ? AND m2.receiver_id = u.id)) AND m2.group_id IS NULL AND (CASE WHEN m2.sender_id = ? THEN m2.is_deleted_sender ELSE m2.is_deleted_receiver END = 0) ORDER BY m2.created_at DESC LIMIT 1) as last_message,
               (SELECT sender_id FROM messages m2 WHERE ((m2.sender_id = u.id AND m2.receiver_id = ?) OR (m2.sender_id = ? AND m2.receiver_id = u.id)) AND m2.group_id IS NULL AND (CASE WHEN m2.sender_id = ? THEN m2.is_deleted_sender ELSE m2.is_deleted_receiver END = 0) ORDER BY m2.created_at DESC LIMIT 1) as last_message_sender_id,
               (SELECT is_read FROM messages m2 WHERE ((m2.sender_id = u.id AND m2.receiver_id = ?) OR (m2.sender_id = ? AND m2.receiver_id = u.id)) AND m2.group_id IS NULL AND (CASE WHEN m2.sender_id = ? THEN m2.is_deleted_sender ELSE m2.is_deleted_receiver END = 0) ORDER BY m2.created_at DESC LIMIT 1) as last_message_is_read,
               (SELECT created_at FROM messages m2 WHERE ((m2.sender_id = u.id AND m2.receiver_id = ?) OR (m2.sender_id = ? AND m2.receiver_id = u.id)) AND m2.group_id IS NULL AND (CASE WHEN m2.sender_id = ? THEN m2.is_deleted_sender ELSE m2.is_deleted_receiver END = 0) ORDER BY m2.created_at DESC LIMIT 1) as last_message_time,
               (SELECT COUNT(*) FROM messages m4 WHERE m4.sender_id = u.id AND m4.receiver_id = ? AND m4.is_read = 0 AND m4.group_id IS NULL AND m4.is_deleted_receiver = 0) as unread_count,
               (SELECT COUNT(*) FROM muted_chats mc WHERE mc.user_id = ? AND mc.muted_user_id = u.id AND (mc.expires_at IS NULL OR mc.expires_at > CURRENT_TIMESTAMP)) > 0 as is_muted,
               (SELECT COUNT(*) FROM archived_chats ac WHERE ac.user_id = ? AND ac.archived_user_id = u.id) > 0 as is_archived,
               (SELECT COUNT(*) FROM pinned_chats pc WHERE pc.user_id = ? AND pc.pinned_user_id = u.id) > 0 as is_pinned
        FROM messages m JOIN users u ON u.id = CASE WHEN m.sender_id = ? THEN m.receiver_id ELSE m.sender_id END
        LEFT JOIN nicknames n ON n.user_id = ? AND n.target_user_id = u.id
        WHERE (m.sender_id = ? OR m.receiver_id = ?) AND m.group_id IS NULL AND (CASE WHEN m.sender_id = ? THEN m.is_deleted_sender ELSE m.is_deleted_receiver END = 0)
        GROUP BY u.id HAVING last_message IS NOT NULL AND is_archived = 0
    """, (user_id, user_id, user_id, user_id, user_id, user_id, user_id, user_id, user_id, user_id, user_id, user_id, user_id, user_id, user_id, user_id, user_id, user_id, user_id, user_id, user_id))

    group_chats = db.query("""
        SELECT g.id as user_id, g.name as username, g.image_url as profile_pic, 'group' as type,
               (SELECT content FROM messages m WHERE m.group_id = g.id ORDER BY m.created_at DESC LIMIT 1) as last_message,
               (SELECT created_at FROM messages m WHERE m.group_id = g.id ORDER BY m.created_at DESC LIMIT 1) as last_message_time,
               0 as unread_count, 0 as is_archived,
               (SELECT COUNT(*) FROM pinned_groups pg WHERE pg.user_id = ? AND pg.group_id = g.id) > 0 as is_pinned
        FROM groups g JOIN group_members gm ON gm.group_id = g.id WHERE gm.user_id = ?
    """, (user_id, user_id))
    
    conversations = [dict(c) for c in private_chats + group_chats]
    now = datetime.utcnow() + timedelta(hours=8)
    for d in conversations:
        if d['last_message_time']:
            try:
                dt = datetime.strptime(d['last_message_time'], '%Y-%m-%d %H:%M:%S') + timedelta(hours=8)
                diff = now.date() - dt.date()
                d['last_message_time'] = dt.strftime('%I:%M %p').lower() if diff.days == 0 else 'Yesterday' if diff.days == 1 else dt.strftime('%A') if diff.days < 7 else dt.strftime('%d/%m/%y')
                d['timestamp'] = int(dt.timestamp())
            except: d['timestamp'] = 0
        else: d['timestamp'] = 0
    
    conversations.sort(key=lambda x: (x['is_pinned'], x['timestamp']), reverse=True)
    archived_count = db.query("SELECT COUNT(*) as count FROM archived_chats WHERE user_id = ?", (user_id,), one=True)['count']
    return render_template('messages/index.html', conversations=conversations, users=users, archived_count=archived_count)

@messages_bp.route('/messages/<int:user_id>')
@login_required
def chat(user_id):
    db, current_user_id = get_db(), session['user_id']
    other_user = db.query("SELECT u.*, COALESCE(n.nickname, u.username) as display_name FROM users u LEFT JOIN nicknames n ON n.user_id = ? AND n.target_user_id = u.id WHERE u.id = ?", (current_user_id, user_id), one=True)
    if not other_user: return "User not found", 404
    messages_data = db.query("SELECT * FROM messages WHERE ((sender_id = ? AND receiver_id = ? AND is_deleted_sender = 0) OR (sender_id = ? AND receiver_id = ? AND is_deleted_receiver = 0)) ORDER BY created_at ASC", (current_user_id, user_id, user_id, current_user_id))
    formatted_messages = []
    for msg in messages_data:
        m = dict(msg)
        try:
            dt = datetime.strptime(m['created_at'], '%Y-%m-%d %H:%M:%S') + timedelta(hours=8)
            m['display_time'] = dt.strftime('%I:%M %p').lower()
            if m['read_at']: m['display_read_at'] = (datetime.strptime(m['read_at'], '%Y-%m-%d %H:%M:%S') + timedelta(hours=8)).strftime('%I:%M %p').lower()
        except: pass
        
        m['reactions'] = db.query("""
            SELECT mr.reaction, COUNT(*) as count, u.profile_pic, u.username
            FROM message_reactions mr JOIN users u ON mr.user_id = u.id WHERE mr.message_id = ? GROUP BY mr.reaction
        """, (m['id'],))
        
        if m.get('reply_to'):
            m['reply_to_message'] = db.query("SELECT m.content, m.sender_id, u.username as sender_name FROM messages m JOIN users u ON m.sender_id = u.id WHERE m.id = ?", (m['reply_to'],), one=True)
            
        formatted_messages.append(m)
        
    conn = get_conn()
    conn.execute("UPDATE messages SET is_read = 1, read_at = COALESCE(read_at, ?) WHERE sender_id = ? AND receiver_id = ? AND is_read = 0", (datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'), user_id, current_user_id))
    conn.commit()
    socketio.emit('read_receipt', {'reader_id': current_user_id, 'sender_id': user_id}, room=f"user_{user_id}")
    return render_template('messages/chat.html', messages=formatted_messages, other_user=other_user, current_user_id=current_user_id)

@messages_bp.route('/messages/send/<int:recipient_id>', methods=['POST'])
@login_required
def send_message(recipient_id):
    content, sender_id, reply_to = request.form.get('content', '').strip(), session['user_id'], request.form.get('reply_to')
    if not content: return jsonify({'status': 'error'}), 400
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO messages (sender_id, receiver_id, content, reply_to) VALUES (?, ?, ?, ?)", (sender_id, recipient_id, content, reply_to))
    message_id = cursor.lastrowid
    conn.execute("DELETE FROM archived_chats WHERE (user_id = ? AND archived_user_id = ?) OR (user_id = ? AND archived_user_id = ?)", (sender_id, recipient_id, recipient_id, sender_id))
    conn.commit()
    
    display_time = datetime.now().strftime('%I:%M %p').lower()
    msg_data = {
        'id': message_id,
        'content': content,
        'display_time': display_time,
        'sender_id': sender_id,
        'reply_to': reply_to
    }
    
    socketio.emit('new_message', msg_data, room=f"user_{recipient_id}")
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest': 
        return jsonify({'status': 'success', 'message': msg_data})
    return redirect(url_for('messages.chat', user_id=recipient_id))

@messages_bp.route('/messages/group/send/<int:group_id>', methods=['POST'])
@login_required
def send_group_message(group_id):
    content, uid, reply_to = request.form.get('content', '').strip(), session['user_id'], request.form.get('reply_to')
    if not content: return jsonify({'status': 'error'}), 400
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO messages (sender_id, receiver_id, content, group_id, reply_to) VALUES (?, ?, ?, ?, ?)", (uid, 0, content, group_id, reply_to))
    mid = cursor.lastrowid
    conn.commit()
    
    display_time = datetime.now().strftime('%I:%M %p').lower()
    
    # Get sender display name for real-time update
    sender = get_db().query("SELECT COALESCE(n.nickname, u.username) as display_name FROM users u LEFT JOIN nicknames n ON n.user_id = ? AND n.target_user_id = u.id WHERE u.id = ?", (uid, uid), one=True)
    sender_display_name = sender['display_name'] if sender else "Unknown"

    msg_data = {
        'id': mid,
        'content': content,
        'display_time': display_time,
        'sender_id': uid,
        'group_id': group_id,
        'sender_display_name': sender_display_name,
        'reply_to': reply_to
    }
    
    socketio.emit('new_message', msg_data, room=f"group_{group_id}")
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest': 
        return jsonify({'status': 'success', 'message': msg_data})
    return redirect(url_for('messages.group_chat', group_id=group_id))

@messages_bp.route('/messages/upload/<int:recipient_id>', methods=['POST'])
@messages_bp.route('/messages/group/<int:group_id>/upload', methods=['POST'])
@login_required
def upload_media(recipient_id=None, group_id=None):
    if 'file' not in request.files:
        return jsonify({'status': 'error', 'message': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'status': 'error', 'message': 'No selected file'}), 400
    
    if file:
        uid = session['user_id']
        filename = secure_filename(file.filename)
        
        if not '.' in filename:
            mimetype = file.mimetype
            if mimetype == 'audio/webm': filename += '.webm'
            elif mimetype == 'audio/ogg': filename += '.ogg'
            elif mimetype == 'audio/wav': filename += '.wav'
            else: filename += '.bin'

        unique_filename = f"{uuid.uuid4()}_{filename}"
        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)
        
        content = f"/static/uploads/{unique_filename}"
        reply_to = request.form.get('reply_to')
        conn = get_conn()
        cursor = conn.cursor()
        
        try:
            if group_id:
                cursor.execute("INSERT INTO messages (sender_id, receiver_id, content, group_id, reply_to) VALUES (?, ?, ?, ?, ?)", (uid, 0, content, group_id, reply_to))
            else:
                cursor.execute("INSERT INTO messages (sender_id, receiver_id, content, reply_to) VALUES (?, ?, ?, ?)", (uid, recipient_id, content, reply_to))
            
            message_id = cursor.lastrowid
            if not group_id:
                conn.execute("DELETE FROM archived_chats WHERE (user_id = ? AND archived_user_id = ?) OR (user_id = ? AND archived_user_id = ?)", (uid, recipient_id, recipient_id, uid))
            conn.commit()
            
            display_time = datetime.now().strftime('%I:%M %p').lower()
            
            # Get sender display name for real-time update
            sender = get_db().query("SELECT COALESCE(n.nickname, u.username) as display_name FROM users u LEFT JOIN nicknames n ON n.user_id = ? AND n.target_user_id = u.id WHERE u.id = ?", (uid, uid), one=True)
            sender_display_name = sender['display_name'] if sender else "Unknown"

            msg_data = {
                'id': message_id,
                'content': content,
                'display_time': display_time,
                'sender_id': uid,
                'sender_display_name': sender_display_name,
                'reply_to': reply_to
            }
            if group_id:
                msg_data['group_id'] = group_id
                socketio.emit('new_message', msg_data, room=f"group_{group_id}")
            else:
                socketio.emit('new_message', msg_data, room=f"user_{recipient_id}")
                
            return jsonify({'status': 'success', 'message': msg_data})
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500

@messages_bp.route('/messages/archived')
@login_required
def archived_chats_view():
    db, user_id = get_db(), session['user_id']
    archived_rows = db.query("""
        SELECT u.id as user_id, COALESCE(n.nickname, u.username) as username, u.profile_pic, 'private' as type,
               (SELECT content FROM messages m2 WHERE ((m2.sender_id = u.id AND m2.receiver_id = ?) OR (m2.sender_id = ? AND m2.receiver_id = u.id)) AND m2.group_id IS NULL AND (CASE WHEN m2.sender_id = ? THEN m2.is_deleted_sender ELSE m2.is_deleted_receiver END = 0) ORDER BY m2.created_at DESC LIMIT 1) as last_message,
               (SELECT created_at FROM messages m2 WHERE ((m2.sender_id = u.id AND m2.receiver_id = ?) OR (m2.sender_id = ? AND m2.receiver_id = u.id)) AND m2.group_id IS NULL AND (CASE WHEN m2.sender_id = ? THEN m2.is_deleted_sender ELSE m2.is_deleted_receiver END = 0) ORDER BY m2.created_at DESC LIMIT 1) as last_message_time
        FROM archived_chats ac JOIN users u ON u.id = ac.archived_user_id LEFT JOIN nicknames n ON n.user_id = ac.user_id AND n.target_user_id = u.id
        WHERE ac.user_id = ?
    """, (user_id, user_id, user_id, user_id, user_id, user_id, user_id))
    
    archived = [dict(r) for r in archived_rows]
    now = datetime.utcnow() + timedelta(hours=8)
    for d in archived:
        if d['last_message_time']:
            try:
                dt = datetime.strptime(d['last_message_time'], '%Y-%m-%d %H:%M:%S') + timedelta(hours=8)
                diff = now.date() - dt.date()
                d['last_message_time'] = dt.strftime('%I:%M %p').lower() if diff.days == 0 else 'Yesterday' if diff.days == 1 else dt.strftime('%A') if diff.days < 7 else dt.strftime('%d/%m/%y')
            except: pass
            
    return render_template('messages/archived.html', archived_chats=archived)

@messages_bp.route('/calls')
@login_required
def calls_list():
    user_id = session['user_id']
    calls_rows = get_db().query("""
        SELECT c.*, u.username as other_username, u.profile_pic as other_profile_pic, CASE WHEN c.caller_id = ? THEN 1 ELSE 0 END as is_outgoing
        FROM calls c JOIN users u ON u.id = CASE WHEN c.caller_id = ? THEN c.receiver_id ELSE c.caller_id END
        WHERE c.caller_id = ? OR c.receiver_id = ? ORDER BY c.started_at DESC LIMIT 50
    """, (user_id, user_id, user_id, user_id))
    
    calls = []
    for row in calls_rows:
        d = dict(row)
        if d['started_at']:
            try:
                dt = datetime.strptime(d['started_at'], '%Y-%m-%d %H:%M:%S') + timedelta(hours=8)
                d['display_date'] = dt.strftime('%d/%m/%y')
                d['display_time'] = dt.strftime('%I:%M %p').lower()
            except:
                d['display_date'] = ''
                d['display_time'] = ''
        else:
            d['display_date'] = ''
            d['display_time'] = ''
        calls.append(d)
        
    return render_template('messages/calls.html', calls=calls)

@messages_bp.route('/api/calls/log', methods=['POST'])
@login_required
def log_call():
    data, conn = request.json, get_conn()
    conn.execute("INSERT INTO calls (caller_id, receiver_id, call_type, status) VALUES (?, ?, ?, ?)", (session['user_id'], data.get('receiver_id'), data.get('call_type', 'voice'), data.get('status', 'missed')))
    conn.commit()
    return {'success': True}

@messages_bp.route('/api/users/all')
@login_required
def api_get_all_users():
    uid = session['user_id']
    users = get_db().query("SELECT id, username, profile_pic, bio FROM users WHERE id != ? ORDER BY username", (uid,))
    return jsonify({'status': 'success', 'users': [dict(u) for u in users]})

@messages_bp.route('/api/groups/create', methods=['POST'])
@login_required
def api_create_group():
    data, uid, conn = request.json, session['user_id'], get_conn()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO groups (name, created_by, image_url) VALUES (?, ?, ?)", (data.get('name', 'New Group'), uid, f"https://ui-avatars.com/api/?name={data.get('name', 'G')}&background=random"))
    gid = cursor.lastrowid
    conn.execute("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)", (gid, uid))
    for mid in data.get('member_ids', []): conn.execute("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)", (gid, mid))
    conn.commit()
    return jsonify({'status': 'success', 'redirect_url': url_for('messages.group_chat', group_id=gid)})

@messages_bp.route('/messages/group/<int:group_id>')
@login_required
def group_chat(group_id):
    db, uid = get_db(), session['user_id']
    group = db.query("SELECT * FROM groups WHERE id = ?", (group_id,), one=True)
    if not group: return "Group not found", 404
    
    # Fetch messages with sender display names
    messages_data = db.query("""
        SELECT m.*, u.username as sender_username, COALESCE(n.nickname, u.username) as sender_display_name
        FROM messages m 
        JOIN users u ON u.id = m.sender_id 
        LEFT JOIN nicknames n ON n.user_id = ? AND n.target_user_id = u.id
        WHERE m.group_id = ? ORDER BY m.created_at ASC
    """, (uid, group_id))
    
    formatted_messages = []
    for msg in messages_data:
        m = dict(msg)
        try:
            dt = datetime.strptime(m['created_at'], '%Y-%m-%d %H:%M:%S') + timedelta(hours=8)
            m['display_time'] = dt.strftime('%I:%M %p').lower()
        except: pass
        
        # Fetch reactions
        m['reactions'] = db.query("""
            SELECT mr.reaction, COUNT(*) as count, u.profile_pic, u.username
            FROM message_reactions mr JOIN users u ON mr.user_id = u.id WHERE mr.message_id = ? GROUP BY mr.reaction
        """, (m['id'],))
        
        # Fetch reply details
        if m.get('reply_to'):
            m['reply_to_message'] = db.query("SELECT m.content, m.sender_id, u.username as sender_name FROM messages m JOIN users u ON m.sender_id = u.id WHERE m.id = ?", (m['reply_to'],), one=True)
            
        formatted_messages.append(m)
        
    return render_template('messages/group_chat.html', group=group, messages=formatted_messages, current_user_id=uid)

@messages_bp.route('/messages/delete/<int:message_id>', methods=['POST'])
@login_required
def delete_message(message_id):
    uid, conn = session['user_id'], get_conn()
    for_everyone = request.form.get('for_everyone') == 'true'
    
    msg = get_db().query("SELECT * FROM messages WHERE id = ?", (message_id,), one=True)
    if not msg: return jsonify({'status': 'error', 'message': 'Message not found'})
    
    if msg['sender_id'] != uid and msg['receiver_id'] != uid:
        return jsonify({'status': 'error', 'message': 'Unauthorized'})

    # If for_everyone and user is sender, delete for both
    if for_everyone and msg['sender_id'] == uid:
        conn.execute("UPDATE messages SET is_deleted_sender = 1, is_deleted_receiver = 1 WHERE id = ?", (message_id,))
        # Emit event to remove from UI immediately
        if msg['group_id']:
            socketio.emit('message_deleted', {'message_id': message_id}, room=f"group_{msg['group_id']}")
        else:
            socketio.emit('message_deleted', {'message_id': message_id}, room=f"user_{msg['receiver_id']}")
            socketio.emit('message_deleted', {'message_id': message_id}, room=f"user_{uid}")
            
    else:
        # Delete only for current user
        if msg['sender_id'] == uid:
            conn.execute("UPDATE messages SET is_deleted_sender = 1 WHERE id = ?", (message_id,))
        elif msg['receiver_id'] == uid:
            conn.execute("UPDATE messages SET is_deleted_receiver = 1 WHERE id = ?", (message_id,))
            
    conn.commit()
    return jsonify({'status': 'success'})

@messages_bp.route('/messages/delete-batch', methods=['POST'])
@login_required
def delete_batch_messages():
    uid, conn = session['user_id'], get_conn()
    message_ids = request.form.getlist('message_ids[]')
    for_everyone = request.form.get('for_everyone') == 'true'
    
    if not message_ids: return jsonify({'status': 'error', 'message': 'No messages selected'})

    for mid in message_ids:
        msg = get_db().query("SELECT * FROM messages WHERE id = ?", (mid,), one=True)
        if not msg: continue
        
        if msg['sender_id'] != uid and msg['receiver_id'] != uid: continue

        if for_everyone and msg['sender_id'] == uid:
            conn.execute("UPDATE messages SET is_deleted_sender = 1, is_deleted_receiver = 1 WHERE id = ?", (mid,))
            # Emit event
            if msg['group_id']:
                socketio.emit('message_deleted', {'message_id': mid}, room=f"group_{msg['group_id']}")
            else:
                socketio.emit('message_deleted', {'message_id': mid}, room=f"user_{msg['receiver_id']}")
                socketio.emit('message_deleted', {'message_id': mid}, room=f"user_{uid}")
        else:
            if msg['sender_id'] == uid:
                conn.execute("UPDATE messages SET is_deleted_sender = 1 WHERE id = ?", (mid,))
            elif msg['receiver_id'] == uid:
                conn.execute("UPDATE messages SET is_deleted_receiver = 1 WHERE id = ?", (mid,))
                
    conn.commit()
    return jsonify({'status': 'success'})

@messages_bp.route('/messages/edit/<int:message_id>', methods=['POST'])
@login_required
def edit_message(message_id):
    uid, conn = session['user_id'], get_conn()
    content = request.form.get('content')
    
    if not content:
        return jsonify({'status': 'error', 'message': 'Content is required'})

    msg = get_db().query("SELECT * FROM messages WHERE id = ?", (message_id,), one=True)
    if not msg:
        return jsonify({'status': 'error', 'message': 'Message not found'})
    
    if msg['sender_id'] != uid:
        return jsonify({'status': 'error', 'message': 'Unauthorized'})

    # Update content
    conn.execute("UPDATE messages SET content = ? WHERE id = ?", (content, message_id))
    conn.commit()
    
    # Emit event
    update_data = {'id': message_id, 'content': content, 'group_id': msg['group_id']}
    
    if msg['group_id']:
        socketio.emit('message_update', update_data, room=f"group_{msg['group_id']}")
    else:
        socketio.emit('message_update', update_data, room=f"user_{msg['receiver_id']}")
        socketio.emit('message_update', update_data, room=f"user_{uid}")
        
    return jsonify({'status': 'success'})

@messages_bp.route('/messages/delete-chat/<int:user_id>', methods=['POST'])
@login_required
def delete_chat_conversation(user_id):
    uid, conn = session['user_id'], get_conn()
    conn.execute("UPDATE messages SET is_deleted_sender = 1 WHERE sender_id = ? AND receiver_id = ?", (uid, user_id))
    conn.execute("UPDATE messages SET is_deleted_receiver = 1 WHERE sender_id = ? AND receiver_id = ?", (user_id, uid))
    conn.commit()
    return jsonify({'status': 'success'})

@messages_bp.route('/api/chats/nickname/<int:target_user_id>', methods=['GET', 'POST'])
@login_required
def handle_nickname(target_user_id):
    uid, conn = session['user_id'], get_conn()
    if request.method == 'GET':
        nn = get_db().query("SELECT nickname FROM nicknames WHERE user_id = ? AND target_user_id = ?", (uid, target_user_id), one=True)
        return jsonify({'status': 'success', 'nickname': nn['nickname'] if nn else None})
    nickname = request.json.get('nickname', '').strip()
    conn.execute("DELETE FROM nicknames WHERE user_id = ? AND target_user_id = ?", (uid, target_user_id))
    if nickname: conn.execute("INSERT INTO nicknames (user_id, target_user_id, nickname) VALUES (?, ?, ?)", (uid, target_user_id, nickname))
    conn.commit()
    return jsonify({'status': 'success', 'nickname': nickname})

@messages_bp.route('/messages/search/<int:user_id>')
@login_required
def search_messages(user_id):
    query, uid = request.args.get('q', '').strip(), session['user_id']
    if not query: return jsonify({'status': 'success', 'results': []})
    results = get_db().query("SELECT id, content, created_at FROM messages WHERE ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)) AND content LIKE ? ORDER BY created_at DESC", (uid, user_id, user_id, uid, f"%{query}%"))
    return jsonify({'status': 'success', 'results': [dict(r) for r in results]})

@messages_bp.route('/messages/react/<int:message_id>', methods=['POST'])
@login_required
def react_to_message(message_id):
    uid, reaction, conn = session['user_id'], request.form.get('reaction'), get_conn()
    if not reaction: return {'status': 'error'}, 400
    existing = get_db().query("SELECT * FROM message_reactions WHERE message_id = ? AND user_id = ? AND reaction = ?", (message_id, uid, reaction))
    if existing: conn.execute("DELETE FROM message_reactions WHERE message_id = ? AND user_id = ? AND reaction = ?", (message_id, uid, reaction))
    else: conn.execute("INSERT INTO message_reactions (message_id, user_id, reaction) VALUES (?, ?, ?)", (message_id, uid, reaction))
    conn.commit()
    counts = get_db().query("SELECT mr.reaction, COUNT(*) as count, u.profile_pic, u.username FROM message_reactions mr JOIN users u ON mr.user_id = u.id WHERE mr.message_id = ? GROUP BY mr.reaction", (message_id,))
    reactions_list = [{'reaction': r['reaction'], 'count': r['count'], 'avatar': r['profile_pic'] or f"https://ui-avatars.com/api/?name={r['username']}&background=random"} for r in counts]
    msg = get_db().query("SELECT group_id FROM messages WHERE id = ?", (message_id,), one=True)
    socketio.emit('message_reaction', {'message_id': message_id, 'reactions': reactions_list}, room=f"group_{msg['group_id']}" if msg['group_id'] else f"user_{uid}")
    return jsonify({'status': 'success', 'reactions': reactions_list})

@messages_bp.route('/api/chats/archive/<int:user_id>', methods=['POST'])
@login_required
def archive_chat(user_id):
    uid, conn = session['user_id'], get_conn()
    conn.execute("INSERT OR IGNORE INTO archived_chats (user_id, archived_user_id) VALUES (?, ?)", (uid, user_id))
    conn.commit()
    return jsonify({'status': 'success'})

@messages_bp.route('/api/chats/unarchive/<int:user_id>', methods=['POST'])
@login_required
def unarchive_chat(user_id):
    uid, conn = session['user_id'], get_conn()
    conn.execute("DELETE FROM archived_chats WHERE user_id = ? AND archived_user_id = ?", (uid, user_id))
    conn.commit()
    return jsonify({'status': 'success'})

@messages_bp.route('/messages/pin/<int:message_id>', methods=['POST'])
@login_required
def pin_message(message_id):
    db = get_db()
    msg = db.query("SELECT * FROM messages WHERE id = ?", (message_id,), one=True)
    if not msg:
        return jsonify({'status': 'error', 'message': 'Message not found'}), 404
    new_val = 0 if msg['is_pinned'] else 1
    conn = get_conn()
    conn.execute("UPDATE messages SET is_pinned = ? WHERE id = ?", (new_val, message_id))
    conn.commit()
    return jsonify({'status': 'success', 'is_pinned': bool(new_val)})

@messages_bp.route('/api/chats/pin/<int:user_id>', methods=['POST'])
@login_required
def pin_chat(user_id):
    uid, conn = session['user_id'], get_conn()
    existing = get_db().query("SELECT * FROM pinned_chats WHERE user_id = ? AND pinned_user_id = ?", (uid, user_id))
    if existing: conn.execute("DELETE FROM pinned_chats WHERE user_id = ? AND pinned_user_id = ?", (uid, user_id))
    else: conn.execute("INSERT INTO pinned_chats (user_id, pinned_user_id) VALUES (?, ?)", (uid, user_id))
    conn.commit()
    return jsonify({'status': 'success', 'pinned': not existing})

@messages_bp.route('/api/chats/pin_group/<int:group_id>', methods=['POST'])
@login_required
def pin_group(group_id):
    uid, conn = session['user_id'], get_conn()
    existing = get_db().query("SELECT * FROM pinned_groups WHERE user_id = ? AND group_id = ?", (uid, group_id))
    if existing: conn.execute("DELETE FROM pinned_groups WHERE user_id = ? AND group_id = ?", (uid, group_id))
    else: conn.execute("INSERT INTO pinned_groups (user_id, group_id) VALUES (?, ?)", (uid, group_id))
    conn.commit()
    return jsonify({'status': 'success', 'pinned': not existing})
