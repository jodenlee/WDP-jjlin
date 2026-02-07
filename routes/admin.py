from flask import Blueprint, render_template, redirect, url_for, session, flash, request
from utils import get_db, login_required

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

def admin_required(f):
    """Decorator to require admin access"""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'warning')
            return redirect(url_for('auth.login'))
        
        db = get_db()
        user = db.query("SELECT * FROM users WHERE id = ?", (session['user_id'],), one=True)
        if not user:
            flash('Admin access required.', 'danger')
            return redirect(url_for('main.home'))
        
        try:
            is_admin = user['is_admin']
        except (KeyError, IndexError):
            is_admin = False
        
        if not is_admin:
            flash('Admin access required.', 'danger')
            return redirect(url_for('main.home'))
        
        return f(*args, **kwargs)
    return decorated_function

@admin_bp.route('/dashboard')
@admin_required
def admin_dashboard():
    """Admin dashboard with statistics"""
    db = get_db()
    
    # Get counts
    user_count = db.query("SELECT COUNT(*) as count FROM users", one=True)['count']
    story_count = db.query("SELECT COUNT(*) as count FROM stories", one=True)['count']
    
    try:
        group_count = db.query("SELECT COUNT(*) as count FROM groups", one=True)['count']
    except:
        group_count = 0
    
    try:
        activity_count = db.query("SELECT COUNT(*) as count FROM activities", one=True)['count']
    except:
        activity_count = 0
    
    # Get pending reports
    try:
        reports = db.query("""
            SELECT r.*, u.username as reporter_name 
            FROM reports r 
            JOIN users u ON r.reporter_id = u.id 
            WHERE r.status = 'pending'
            ORDER BY r.created_at DESC
            LIMIT 10
        """)
    except:
        reports = []
    
    stats = {
        'users': user_count,
        'stories': story_count,
        'groups': group_count,
        'activities': activity_count
    }
    
    return render_template('admin/dashboard.html', stats=stats, reports=reports)

@admin_bp.route('/users')
@admin_required
def users_list():
    """List all users"""
    db = get_db()
    
    role_filter = request.args.get('role', '')
    search = request.args.get('search', '')
    
    query = "SELECT * FROM users WHERE 1=1"
    params = []
    
    if role_filter:
        query += " AND role = ?"
        params.append(role_filter)
    
    if search:
        query += " AND (username LIKE ? OR email LIKE ? OR full_name LIKE ?)"
        params.extend([f'%{search}%', f'%{search}%', f'%{search}%'])
    
    query += " ORDER BY created_at DESC"
    
    users = db.query(query, params)
    
    return render_template('admin/users.html', users=users, role_filter=role_filter, search=search)

@admin_bp.route('/users/<int:user_id>')
@admin_required
def user_detail(user_id):
    """View user details"""
    db = get_db()
    
    user = db.query("SELECT * FROM users WHERE id = ?", (user_id,), one=True)
    if not user:
        flash('User not found.', 'warning')
        return redirect(url_for('admin.users_list'))
    
    # Get user's stories
    stories = db.query("SELECT * FROM stories WHERE author_id = ? ORDER BY created_at DESC LIMIT 5", (user_id,))
    
    # Get user's stats
    story_count = db.query("SELECT COUNT(*) as count FROM stories WHERE author_id = ?", (user_id,), one=True)['count']
    comment_count = db.query("SELECT COUNT(*) as count FROM comments WHERE user_id = ?", (user_id,), one=True)['count']
    
    stats = {
        'stories': story_count,
        'comments': comment_count
    }
    
    return render_template('admin/user_detail.html', user=user, stories=stories, stats=stats)

@admin_bp.route('/users/<int:user_id>/toggle_admin', methods=['POST'])
@admin_required
def toggle_admin(user_id):
    """Toggle admin status for a user"""
    db = get_db()
    
    user = db.query("SELECT * FROM users WHERE id = ?", (user_id,), one=True)
    if not user:
        flash('User not found.', 'warning')
        return redirect(url_for('admin.users_list'))
    
    # Don't allow removing own admin status
    if user_id == session['user_id']:
        flash('Cannot modify your own admin status.', 'danger')
        return redirect(url_for('admin.user_detail', user_id=user_id))
    
    try:
        current_is_admin = user['is_admin']
    except (KeyError, IndexError):
        current_is_admin = False
    
    new_status = 0 if current_is_admin else 1
    conn = db.get_connection()
    conn.execute("UPDATE users SET is_admin = ? WHERE id = ?", (new_status, user_id))
    conn.commit()
    
    flash(f"Admin status {'granted' if new_status else 'revoked'} for {user['username']}.", 'success')
    return redirect(url_for('admin.user_detail', user_id=user_id))

@admin_bp.route('/reports')
@admin_required
def reports_list():
    """List all reports"""
    db = get_db()
    
    status_filter = request.args.get('status', '')  # Default to all reports
    
    query = """
        SELECT r.*, u.username as reporter 
        FROM reports r 
        JOIN users u ON r.reporter_id = u.id
    """
    params = []
    
    if status_filter:
        query += " WHERE r.status = ?"
        params.append(status_filter)
    
    query += " ORDER BY r.created_at DESC"
    
    reports = db.query(query, params)
    
    return render_template('admin/reports.html', reports=reports, status_filter=status_filter)

@admin_bp.route('/reports/<int:report_id>/resolve', methods=['POST'])
@admin_required
def resolve_report(report_id):
    """Resolve a report"""
    action = request.form.get('action', 'dismiss')
    
    db = get_db()
    conn = db.get_connection()
    
    if action == 'delete':
        # Get the report details
        report = db.query("SELECT * FROM reports WHERE id = ?", (report_id,), one=True)
        if report:
            # Delete the target content based on type
            if report['target_type'] == 'story':
                conn.execute("DELETE FROM stories WHERE id = ?", (report['target_id'],))
            elif report['target_type'] == 'comment':
                conn.execute("DELETE FROM comments WHERE id = ?", (report['target_id'],))
            elif report['target_type'] == 'group':
                conn.execute("DELETE FROM groups WHERE id = ?", (report['target_id'],))
        
        conn.execute("UPDATE reports SET status = 'resolved' WHERE id = ?", (report_id,))
        flash('Content deleted and report resolved.', 'success')
    else:
        conn.execute("UPDATE reports SET status = 'dismissed' WHERE id = ?", (report_id,))
        flash('Report dismissed.', 'info')
    
    conn.commit()
    return redirect(url_for('admin.reports_list'))

@admin_bp.route('/reports/all')
@admin_required
def admin_reports():
    db = get_db()
    filter_type = request.args.get('type')  # story, activity, group, comment
    
    # Base query
    base_query = """
        SELECT r.*, u.username as reporter_name 
        FROM reports r 
        LEFT JOIN users u ON r.reporter_id = u.id
    """
    
    # Build where clause for type filter
    where_clause = ""
    params = ()
    if filter_type and filter_type in ['story', 'activity', 'group', 'comment']:
        where_clause = " WHERE r.target_type = ?"
        params = (filter_type,)
    
    # Get reports by status
    pending_query = base_query + where_clause + (" AND" if where_clause else " WHERE") + " r.status = 'pending' ORDER BY r.created_at DESC"
    deleted_query = base_query + where_clause + (" AND" if where_clause else " WHERE") + " r.status = 'resolved_deleted' ORDER BY r.created_at DESC"
    dismissed_query = base_query + where_clause + (" AND" if where_clause else " WHERE") + " r.status = 'dismissed' ORDER BY r.created_at DESC"
    
    pending_reports = db.query(pending_query, params)
    deleted_reports = db.query(deleted_query, params)
    dismissed_reports = db.query(dismissed_query, params)
    
    # Get counts for filter badges
    counts = {
        'all': db.query("SELECT COUNT(*) as c FROM reports WHERE status = 'pending'")[0]['c'],
        'story': db.query("SELECT COUNT(*) as c FROM reports WHERE status = 'pending' AND target_type = 'story'")[0]['c'],
        'activity': db.query("SELECT COUNT(*) as c FROM reports WHERE status = 'pending' AND target_type = 'activity'")[0]['c'],
        'group': db.query("SELECT COUNT(*) as c FROM reports WHERE status = 'pending' AND target_type = 'group'")[0]['c'],
        'comment': db.query("SELECT COUNT(*) as c FROM reports WHERE status = 'pending' AND target_type = 'comment'")[0]['c'],
    }
    
    return render_template('admin/reports.html', 
                          pending_reports=pending_reports,
                          deleted_reports=deleted_reports,
                          dismissed_reports=dismissed_reports,
                          filter_type=filter_type,
                          counts=counts)

@admin_bp.route('/reports/view/<target_type>/<int:target_id>')
@admin_required
def view_reported_item(target_type, target_id):
    """Redirect to view the reported content"""
    if target_type == 'story':
        return redirect(url_for('stories.view_story', story_id=target_id))
    elif target_type == 'activity':
        return redirect(url_for('activities.view_activity', activity_id=target_id))
    elif target_type == 'group':
        return redirect(url_for('community.view_group', group_id=target_id))
    elif target_type == 'comment':
        flash('Comment viewing is not available directly.', 'info')
        return redirect(url_for('admin.admin_reports'))
    else:
        flash('Unknown content type.', 'warning')
        return redirect(url_for('admin.admin_reports'))

@admin_bp.route('/reports/<int:report_id>/delete', methods=['POST'])
@admin_required
def delete_reported_item(report_id):
    """Delete reported content and update report status"""
    db = get_db()
    conn = db.get_connection()
    
    report = db.query("SELECT * FROM reports WHERE id = ?", (report_id,), one=True)
    if not report:
        flash('Report not found.', 'warning')
        return redirect(url_for('admin.admin_reports'))
    
    # Delete the target content based on type
    if report['target_type'] == 'story':
        conn.execute("DELETE FROM stories WHERE id = ?", (report['target_id'],))
    elif report['target_type'] == 'comment':
        conn.execute("DELETE FROM comments WHERE id = ?", (report['target_id'],))
    elif report['target_type'] == 'group':
        conn.execute("DELETE FROM groups WHERE id = ?", (report['target_id'],))
    elif report['target_type'] == 'activity':
        conn.execute("DELETE FROM activities WHERE id = ?", (report['target_id'],))
    
    # Update report status to resolved_deleted
    conn.execute("UPDATE reports SET status = 'resolved_deleted' WHERE id = ?", (report_id,))
    conn.commit()
    
    flash('Content deleted and report resolved.', 'success')
    return redirect(url_for('admin.admin_reports'))

@admin_bp.route('/reports/<int:report_id>/dismiss', methods=['POST'])
@admin_required
def dismiss_report(report_id):
    """Dismiss a report without deleting content"""
    db = get_db()
    conn = db.get_connection()
    
    conn.execute("UPDATE reports SET status = 'dismissed' WHERE id = ?", (report_id,))
    conn.commit()
    
    flash('Report dismissed.', 'info')
    return redirect(url_for('admin.admin_reports'))