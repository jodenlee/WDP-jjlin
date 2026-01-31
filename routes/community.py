from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from utils import get_db, login_required

community_bp = Blueprint('community', __name__)

@community_bp.route('/community')
def index():
    db = get_db()
    groups = db.query("""
        SELECT g.*, 
               (SELECT COUNT(*) FROM group_members WHERE group_id = g.id) as member_count
        FROM groups g
        ORDER BY g.created_at DESC
    """)
    return render_template('community/index.html', groups=groups)

@community_bp.route('/community/new', methods=['GET', 'POST'])
@login_required
def create_group():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form.get('description', '')
        image_url = request.form.get('image_url', '')
        user_id = session['user_id']
        
        db = get_db()
        conn = db.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO groups (name, description, image_url, created_by) VALUES (?, ?, ?, ?)",
            (name, description, image_url, user_id)
        )
        group_id = cursor.lastrowid
        
        # Creator automatically joins the group
        cursor.execute(
            "INSERT INTO group_members (group_id, user_id) VALUES (?, ?)",
            (group_id, user_id)
        )
        conn.commit()
        flash('Group created successfully!', 'success')
        return redirect(url_for('community.index'))
    
    return render_template('community/create.html')

@community_bp.route('/community/<int:group_id>')
def view_group(group_id):
    db = get_db()
    group = db.query("SELECT * FROM groups WHERE id = ?", (group_id,), one=True)
    if not group:
        flash('Group not found.', 'danger')
        return redirect(url_for('community.index'))
    
    member_count = db.query("SELECT COUNT(*) as count FROM group_members WHERE group_id = ?", (group_id,), one=True)['count']
    
    members = db.query("""
        SELECT u.username, u.role
        FROM group_members gm
        JOIN users u ON gm.user_id = u.id
        WHERE gm.group_id = ?
    """, (group_id,))
    
    is_member = False
    if 'user_id' in session:
        check = db.query("SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?", 
                         (group_id, session['user_id']), one=True)
        is_member = bool(check)
    
    return render_template('community/view.html', group=group, member_count=member_count, members=members, is_member=is_member)

@community_bp.route('/community/<int:group_id>/join', methods=['POST'])
@login_required
def join_group(group_id):
    db = get_db()
    user_id = session['user_id']
    
    conn = db.get_connection()
    try:
        conn.execute("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)", (group_id, user_id))
        conn.commit()
        flash('Joined group!', 'success')
    except:
        flash('Already a member or error joining group.', 'info')
        
    return redirect(url_for('community.view_group', group_id=group_id))

@community_bp.route('/community/<int:group_id>/leave', methods=['POST'])
@login_required
def leave_group(group_id):
    db = get_db()
    user_id = session['user_id']
    
    conn = db.get_connection()
    conn.execute("DELETE FROM group_members WHERE group_id = ? AND user_id = ?", (group_id, user_id))
    conn.commit()
    flash('Left group.', 'info')
    
    return redirect(url_for('community.view_group', group_id=group_id))
