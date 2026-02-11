from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from utils import get_db, login_required, create_notification, check_content_moderation
from werkzeug.utils import secure_filename
import os
import time

community_bp = Blueprint('community', __name__)

# Allowed extensions for group images
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'avif'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@community_bp.route('/community')
def community():
    db = get_db()
    search_query = request.args.get('search', '').strip()
    
    query = """
        SELECT g.*, 
               (SELECT COUNT(*) FROM group_members WHERE group_id = g.id) as member_count
        FROM groups g
    """
    params = []
    
    if search_query:
        query += " WHERE g.name LIKE ? OR g.description LIKE ?"
        params.extend([f'%{search_query}%', f'%{search_query}%'])
        
    query += " ORDER BY g.created_at DESC"
    
    groups = db.query(query, params)
    return render_template('community/index.html', groups=groups)

@community_bp.route('/community/new', methods=['GET', 'POST'])
@login_required
def create_group():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        if len(name) < 5:
            flash('Group name needs a minimum of 5 characters.', 'danger')
            return render_template('community/create.html')
            
        description = request.form.get('description', '')
        user_id = session['user_id']
        
        # Handle group image upload
        image_url = None
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename:
                if not allowed_file(file.filename):
                    flash('Only image files are allowed.', 'danger')
                    return render_template('community/create.html')
                
                filename = secure_filename(file.filename)
                # Ensure unique filename
                filename = f"group_{int(time.time())}_{filename}"
                
                # Save file
                file.save(os.path.join(current_app.config['UPLOAD_FOLDER'], 'groups', filename))
                image_url = f"uploads/groups/{filename}"
                
        db = get_db()
        conn = db.get_connection()
        try:
            # FIX: Changed creator_id to created_by to match database schema
            cursor = conn.execute(
                "INSERT INTO groups (name, description, created_by, image_url) VALUES (?, ?, ?, ?)",
                (name, description, user_id, image_url)
            )
            group_id = cursor.lastrowid
            
            # Add creator as a member and admin
            conn.execute(
                "INSERT INTO group_members (group_id, user_id, role) VALUES (?, ?, 'admin')",
                (group_id, user_id)
            )
            conn.commit()
            flash('Group created successfully!', 'success')
            return redirect(url_for('community.view_group', group_id=group_id))
        except Exception as e:
            flash(f'Error creating group: {e}', 'danger')
            return redirect(url_for('community.create_group'))
        finally:
            conn.close()
            
    return render_template('community/create.html')

# REPORT GROUP ACTION: Allows users to report a community group
@community_bp.route('/community/group/<int:group_id>/report', methods=['POST'])
@login_required
def report_group(group_id):
    reason = request.form.get('reason')
    if not reason:
        flash('Please provide a reason for reporting.', 'warning')
        return redirect(request.referrer)
        
    db = get_db()
    conn = db.get_connection()
    user_id = session['user_id']
    
    # Check if already reported
    existing = db.query("SELECT id FROM reports WHERE reporter_id = ? AND target_type = 'group' AND target_id = ?", 
                       (user_id, group_id), one=True)
    
    if existing:
        flash('You have already reported this group.', 'info')
    else:
        conn.execute("INSERT INTO reports (reporter_id, target_type, target_id, reason) VALUES (?, 'group', ?, ?)",
                    (user_id, group_id, reason))
        conn.commit()
        flash('Group reported. Thank you for helping keep our community safe.', 'success')
        
    return redirect(request.referrer)


@community_bp.route('/community/<int:group_id>')
def view_group(group_id):
    db = get_db()
    group = db.query("SELECT * FROM groups WHERE id = ?", (group_id,), one=True)
    if not group:
        flash('Group not found.', 'danger')
        return redirect(url_for('community.community'))
    
    # Calculate total members in the group
    member_count = len(db.query("SELECT * FROM group_members WHERE group_id = ?", (group_id,)))
    
    # Fetch all members of the group, prioritizing the creator
    members = db.query("""
        SELECT u.*, gm.role 
        FROM users u
        JOIN group_members gm ON u.id = gm.user_id
        WHERE gm.group_id = ?
        ORDER BY (u.id = ?) DESC, u.username ASC
    """, (group_id, group['created_by']))
    
    user_id = session.get('user_id')
    is_member = False
    is_owner = False
    
    if user_id:
        membership = db.query("SELECT * FROM group_members WHERE group_id = ? AND user_id = ?", 
                             (group_id, user_id), one=True)
        is_member = bool(membership)
        is_owner = (group['created_by'] == user_id)
    
    # Fetch posts
    posts_query = """
        SELECT p.*, u.username, u.profile_pic, u.role
        FROM group_posts p
        JOIN users u ON p.user_id = u.id
        WHERE p.group_id = ?
        ORDER BY p.created_at DESC
    """
    posts = db.query(posts_query, (group_id,))
    
    posts_data = []
    for post in posts:
        comments_query = """
            SELECT c.*, u.username, u.profile_pic
            FROM group_post_comments c
            JOIN users u ON c.user_id = u.id
            WHERE c.post_id = ?
            ORDER BY c.created_at ASC
        """
        comments = db.query(comments_query, (post['id'],))
        
        is_liked = False
        if user_id:
            like_check = db.query("SELECT * FROM group_post_likes WHERE user_id = ? AND post_id = ?", 
                                (user_id, post['id']), one=True)
            is_liked = bool(like_check)
            
        post_dict = dict(post)
        post_dict['comments'] = comments
        post_dict['is_liked'] = is_liked
        posts_data.append(post_dict)
    
    return render_template('community/view.html', group=group, is_member=is_member, is_owner=is_owner, 
                           member_count=member_count, members=members, posts=posts_data)

@community_bp.route('/community/<int:group_id>/join', methods=['POST'])
@login_required
def join_group(group_id):
    user_id = session['user_id']
    db = get_db()
    conn = db.get_connection()
    try:
        conn.execute("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)", (group_id, user_id))
        conn.commit()
        flash('Joined group!', 'success')
    except:
        pass
    return redirect(url_for('community.view_group', group_id=group_id))

@community_bp.route('/community/<int:group_id>/leave', methods=['POST'])
@login_required
def leave_group(group_id):
    user_id = session['user_id']
    db = get_db()
    conn = db.get_connection()
    conn.execute("DELETE FROM group_members WHERE group_id = ? AND user_id = ?", (group_id, user_id))
    
    # Check if empty
    cursor = conn.execute("SELECT COUNT(*) FROM group_members WHERE group_id = ?", (group_id,))
    count = cursor.fetchone()[0]
    
    if count == 0:
        conn.execute("DELETE FROM groups WHERE id = ?", (group_id,))
        conn.commit()
        flash('Group deleted as it has no members.', 'info')
        return redirect(url_for('community.community'))
        
    conn.commit()
    flash('Left group successfully.', 'info')
    return redirect(url_for('community.view_group', group_id=group_id))

@community_bp.route('/community/<int:group_id>/delete', methods=['POST'])
@login_required
def delete_group(group_id):
    user_id = session['user_id']
    db = get_db()
    group = db.query("SELECT * FROM groups WHERE id = ?", (group_id,), one=True)
    if not group:
         return "Group not found", 404

    if group['created_by'] != user_id:
        flash('Only the group creator can delete the group.', 'danger')
        return redirect(url_for('community.view_group', group_id=group_id))

    conn = db.get_connection()
    conn.execute("DELETE FROM group_members WHERE group_id = ?", (group_id,))
    conn.execute("DELETE FROM groups WHERE id = ?", (group_id,))
    conn.commit()
    flash('Group deleted successfully.', 'success')
    return redirect(url_for('community.community'))

@community_bp.route('/community/<int:group_id>/update', methods=['POST'])
@login_required
def update_group(group_id):
    user_id = session['user_id']
    db = get_db()
    group = db.query("SELECT * FROM groups WHERE id = ?", (group_id,), one=True)
    if not group:
         return "Group not found", 404

    if group['created_by'] != user_id:
        flash('Only the group creator can update the group.', 'danger')
        return redirect(url_for('community.view_group', group_id=group_id))

    name = request.form.get('name', '').strip()
    if len(name) < 5:
        flash('Group name needs a minimum of 5 characters.', 'danger')
        return redirect(url_for('community.view_group', group_id=group_id))

    description = request.form.get('description', '')

    conn = db.get_connection()
    
    if 'image' in request.files:
        file = request.files['image']
        if file and file.filename:
            if not allowed_file(file.filename):
                flash('Only image files are allowed.', 'danger')
                return redirect(url_for('community.view_group', group_id=group_id))
            
            # Delete old image
            if group['image_url']:
                from flask import current_app
                old_image_path = os.path.join(current_app.root_path, 'static', group['image_url'])
                if os.path.exists(old_image_path):
                    os.remove(old_image_path)
            
            filename = secure_filename(file.filename)
            filename = f"group_{int(time.time())}_{filename}"
            from flask import current_app
            filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            image_url = f"uploads/{filename}"
            conn.execute("UPDATE groups SET name = ?, description = ?, image_url = ? WHERE id = ?", 
                        (name, description, image_url, group_id))
        else:
            conn.execute("UPDATE groups SET name = ?, description = ? WHERE id = ?", (name, description, group_id))
    else:
         conn.execute("UPDATE groups SET name = ?, description = ? WHERE id = ?", (name, description, group_id))

    conn.commit()
    flash('Group updated successfully!', 'success')
    return redirect(url_for('community.view_group', group_id=group_id))

@community_bp.route('/community/<int:group_id>/post', methods=['POST'])
@login_required
def create_group_post(group_id):
    user_id = session['user_id']
    content = request.form.get('content', '')
    
    # CONTENT MODERATION CHECK
    if content and check_content_moderation(content):
        flash('Your content has been flagged by our safety system. Please ensure your post follows community guidelines.', 'danger')
        return redirect(url_for('community.view_group', group_id=group_id))

    audio_url = None
    if 'audio' in request.files:
        file = request.files['audio']
        if file and file.filename:
            from flask import current_app
            filename = secure_filename(file.filename)
            # Ensure unique filename with timestamp
            filename = f"post_audio_{int(time.time())}_{filename}"
            
            # Create uploads/posts directory if it doesn't exist
            upload_path = os.path.join(current_app.config['UPLOAD_FOLDER'], 'posts')
            if not os.path.exists(upload_path):
                os.makedirs(upload_path)
                
            file.save(os.path.join(upload_path, filename))
            audio_url = f"uploads/posts/{filename}"

    db = get_db()
    conn = db.get_connection()
    conn.execute(
        "INSERT INTO group_posts (group_id, user_id, content, audio_url) VALUES (?, ?, ?, ?)",
        (group_id, user_id, content, audio_url)
    )
    conn.commit()
    flash('Post created successfully!', 'success')
    return redirect(url_for('community.view_group', group_id=group_id))

@community_bp.route('/community/post/<int:post_id>/update', methods=['POST'])
@login_required
def update_group_post(post_id):
    user_id = session['user_id']
    new_content = request.form['content']
    
    # CONTENT MODERATION CHECK
    if check_content_moderation(new_content):
        flash('Your content has been flagged by our safety system. Please ensure your post follows community guidelines.', 'danger')
        return redirect(request.referrer)

    db = get_db()
    post = db.query("SELECT * FROM group_posts WHERE id = ?", (post_id,), one=True)
    
    if not post:
        return redirect(request.referrer or url_for('community.community'))
        
    if post['user_id'] != user_id:
        flash('You can only edit your own posts.', 'danger')
        return redirect(url_for('community.view_group', group_id=post['group_id']))
        
    conn = db.get_connection()
    conn.execute("UPDATE group_posts SET content = ? WHERE id = ?", (new_content, post_id))
    conn.commit()
    
    flash('Post updated successfully!', 'success')
    return redirect(url_for('community.view_group', group_id=post['group_id']))

@community_bp.route('/community/post/<int:post_id>/delete', methods=['POST'])
@login_required
def delete_group_post(post_id):
    user_id = session['user_id']
    db = get_db()
    post = db.query("SELECT * FROM group_posts WHERE id = ?", (post_id,), one=True)
    
    if not post:
        return redirect(request.referrer or url_for('community.community'))
        
    if post['user_id'] != user_id:
        flash('You can only delete your own posts.', 'danger')
        return redirect(url_for('community.view_group', group_id=post['group_id']))
        
    conn = db.get_connection()
    conn.execute("DELETE FROM group_post_comments WHERE post_id = ?", (post_id,))
    conn.execute("DELETE FROM group_posts WHERE id = ?", (post_id,))
    conn.commit()
    
    flash('Post deleted successfully!', 'success')
    return redirect(url_for('community.view_group', group_id=post['group_id']))

@community_bp.route('/community/post/<int:post_id>/like', methods=['POST'])
@login_required
def toggle_group_post_like(post_id):
    user_id = session['user_id']
    db = get_db()
    conn = db.get_connection()
    
    post = db.query("SELECT * FROM group_posts WHERE id = ?", (post_id,), one=True)
    if not post:
        return redirect(request.referrer or url_for('community.community'))
        
    like = db.query("SELECT * FROM group_post_likes WHERE user_id = ? AND post_id = ?", (user_id, post_id), one=True)
    
    if like:
        conn.execute("DELETE FROM group_post_likes WHERE user_id = ? AND post_id = ?", (user_id, post_id))
        conn.execute("UPDATE group_posts SET likes = likes - 1 WHERE id = ?", (post_id,))
    else:
        conn.execute("INSERT INTO group_post_likes (user_id, post_id) VALUES (?, ?)", (user_id, post_id))
        conn.execute("UPDATE group_posts SET likes = likes + 1 WHERE id = ?", (post_id,))
        
    conn.commit()
    
    # Notify Post Author (if liked and not by themselves)
    if not like: # This means it was just liked
        if post['user_id'] != user_id:
            sender = db.query("SELECT username FROM users WHERE id = ?", (user_id,), one=True)
            create_notification(
                post['user_id'],
                'Like',
                f"{sender['username']} liked your post",
                url_for('community.view_group', group_id=post['group_id'])
            )
    
    return redirect(url_for('community.view_group', group_id=post['group_id']))

@community_bp.route('/community/post/<int:post_id>/comment', methods=['POST'])
@login_required
def create_group_post_comment(post_id):
    user_id = session['user_id']
    content = request.form['content']
    
    # CONTENT MODERATION CHECK
    if check_content_moderation(content):
        flash('Your content has been flagged by our safety system. Please ensure your comment follows community guidelines.', 'danger')
        return redirect(request.referrer)

    db = get_db()
    conn = db.get_connection()
    post = db.query("SELECT group_id FROM group_posts WHERE id = ?", (post_id,), one=True)
    if post:
        conn.execute(
            "INSERT INTO group_post_comments (post_id, user_id, content) VALUES (?, ?, ?)",
            (post_id, user_id, content)
        )
        conn.commit()
        
        # Notify Post Author (if not by themselves)
        post_info = db.query("SELECT user_id, group_id FROM group_posts WHERE id = ?", (post_id,), one=True)
        if post_info and post_info['user_id'] != user_id:
            sender = db.query("SELECT username FROM users WHERE id = ?", (user_id,), one=True)
            create_notification(
                post_info['user_id'],
                'Comment',
                f"{sender['username']} commented on your post",
                url_for('community.view_group', group_id=post_info['group_id'])
            )
        flash('Comment posted successfully!', 'success')
    
    if post:
        return redirect(url_for('community.view_group', group_id=post['group_id']))
    else:
        return redirect(url_for('community.community'))

@community_bp.route('/community/post/comment/<int:comment_id>/update', methods=['POST'])
@login_required
def update_group_post_comment(comment_id):
    user_id = session['user_id']
    new_content = request.form['content']
    
    db = get_db()
    comment = db.query("SELECT * FROM group_post_comments WHERE id = ?", (comment_id,), one=True)
    
    if not comment:
        return redirect(request.referrer or url_for('community.community'))
        
    post = db.query("SELECT group_id FROM group_posts WHERE id = ?", (comment['post_id'],), one=True)
    
    if comment['user_id'] != user_id:
        flash('You can only edit your own comments.', 'danger')
        return redirect(url_for('community.view_group', group_id=post['group_id']))
        
    conn = db.get_connection()
    conn.execute("UPDATE group_post_comments SET content = ? WHERE id = ?", (new_content, comment_id))
    conn.commit()
    
    flash('Comment updated successfully!', 'success')
    return redirect(url_for('community.view_group', group_id=post['group_id']))

@community_bp.route('/community/post/comment/<int:comment_id>/delete', methods=['POST'])
@login_required
def delete_group_post_comment(comment_id):
    user_id = session['user_id']
    db = get_db()
    comment = db.query("SELECT * FROM group_post_comments WHERE id = ?", (comment_id,), one=True)
    
    if not comment:
        return redirect(request.referrer or url_for('community.community'))
        
    post = db.query("SELECT group_id FROM group_posts WHERE id = ?", (comment['post_id'],), one=True)

    if comment['user_id'] != user_id:
        flash('You can only delete your own comments.', 'danger')
        return redirect(url_for('community.view_group', group_id=post['group_id']))
        
    conn = db.get_connection()
    conn.execute("DELETE FROM group_post_comments WHERE id = ?", (comment_id,))
    conn.commit()
    
    flash('Comment deleted successfully!', 'success')
    return redirect(url_for('community.view_group', group_id=post['group_id']))
