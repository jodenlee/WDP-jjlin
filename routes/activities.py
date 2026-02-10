import os
import uuid
from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash
from utils import get_db, login_required, allowed_file, create_notification

activities_bp = Blueprint('activities', __name__)

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "pdf", "doc", "docx"}

def activities_unlocked():
    """Check if activities management is unlocked for this session."""
    return bool(session.get("activities_unlocked", False))

def ensure_activity_password():
    """Ensure a default activity password exists in settings."""
    db = get_db()
    if not db.get_setting("activities_password_hash"):
        default_pwd = "activity123" 
        db.set_setting("activities_password_hash", generate_password_hash(default_pwd))

@activities_bp.route('/activities')
def activities_list():
    db = get_db()
    q = (request.args.get('q') or '').strip()
    loc = (request.args.get('location') or '').strip()
    sort = (request.args.get('sort') or 'newest').strip()

    where = []
    params = []

    if q:
        where.append("(a.title LIKE ? OR a.description LIKE ?)")
        like = f"%{q}%"
        params.extend([like, like])

    if loc:
        where.append("(a.location LIKE ?)")
        params.append(f"%{loc}%")

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    if sort == "oldest":
        order_sql = "ORDER BY a.event_date ASC, a.created_at ASC"
    elif sort == "upcoming":
        order_sql = "ORDER BY a.event_date ASC, a.created_at DESC"
    else:
        # Default to newest
        order_sql = "ORDER BY a.event_date DESC, a.created_at DESC"

    query = f"""
        SELECT a.*, 
               (SELECT COUNT(*) FROM activity_rsvps WHERE activity_id = a.id) as rsvp_count
        FROM activities a
        {where_sql}
        {order_sql}
    """
    activities_data = db.query(query, tuple(params))
    
    # Get set of activity IDs the current user has joined
    user_joined_ids = set()
    if 'user_id' in session:
        user_rsvps = db.query("SELECT activity_id FROM activity_rsvps WHERE user_id = ?", (session['user_id'],))
        user_joined_ids = {r['activity_id'] for r in user_rsvps}
    
    return render_template('activities/index.html', activities=activities_data, q=q, loc=loc, sort=sort, user_joined_ids=user_joined_ids)

@activities_bp.route('/activities/<int:activity_id>')
def view_activity(activity_id):
    db = get_db()
    activity = db.query("SELECT * FROM activities WHERE id = ?", (activity_id,), one=True)
    if not activity:
        return "Activity not found", 404
    
    is_joined = False
    rsvp_count = len(db.query("SELECT * FROM activity_rsvps WHERE activity_id = ?", (activity_id,)))
    
    if 'user_id' in session:
        user_id = session['user_id']
        rsvp = db.query("SELECT * FROM activity_rsvps WHERE activity_id = ? AND user_id = ?", (activity_id, user_id), one=True)
        is_joined = bool(rsvp)
    
    return render_template('activities/view.html', activity=activity, is_joined=is_joined, rsvp_count=rsvp_count)

@activities_bp.route("/activities/unlock", methods=["GET", "POST"])
@login_required
def activities_unlock():
    ensure_activity_password()
    if request.method == "POST":
        pwd = request.form.get("password", "")
        db = get_db()
        pwd_hash = db.get_setting("activities_password_hash")

        if pwd_hash and check_password_hash(pwd_hash, pwd):
            session["activities_unlocked"] = True
            flash("Activities management unlocked.", "success")
            # Redirect back to where they were trying to go
            next_url = request.args.get('next') or url_for("activities.activities_list")
            return redirect(next_url)
        else:
            flash("Incorrect password.", "danger")

    return render_template("activities/unlock.html")

@activities_bp.route('/activities/new', methods=['GET', 'POST'])
@login_required
def create_activity():
    if not activities_unlocked():
        return redirect(url_for("activities.activities_unlock", next=url_for("activities.create_activity")))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        activity_type = request.form['type']
        location = request.form.get('location', '')
        event_date = request.form.get('event_date', '')
        
        attachment_filename = None
        file = request.files.get('attachment')

        if file and file.filename:
            if not allowed_file(file.filename, ALLOWED_EXTENSIONS):
                flash('Invalid file type. Allowed: PNG, JPG, JPEG, GIF, PDF, DOC, DOCX', 'danger')
                return redirect(request.url)

            from app import app # To get UPLOAD_FOLDER
            filename = secure_filename(file.filename)
            ext = filename.rsplit('.', 1)[1].lower()
            new_name = f"{uuid.uuid4().hex}.{ext}"
            
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], new_name)
            file.save(save_path)
            attachment_filename = new_name

        user_id = session['user_id']
        db = get_db()
        db.query(
            "INSERT INTO activities (title, description, type, location, event_date, organizer_id, attachment) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (title, description, activity_type, location, event_date, user_id, attachment_filename)
        )
        # Re-lock after successful creation
        session.pop("activities_unlocked", None)
        flash('Activity created successfully!', 'success')
        return redirect(url_for('activities.activities_list'))
    
    return render_template('activities/create.html')

@activities_bp.route("/activities/<int:activity_id>/edit", methods=["GET", "POST"])
@login_required
def edit_activity(activity_id):
    if not activities_unlocked():
        return redirect(url_for("activities.activities_unlock", next=url_for("activities.edit_activity", activity_id=activity_id)))

    db = get_db()
    activity = db.query("SELECT * FROM activities WHERE id = ?", (activity_id,), one=True)

    if not activity:
        return "Activity not found", 404

    if int(activity["organizer_id"]) != int(session["user_id"]):
        flash("You are not authorized to edit this activity.", "danger")
        return redirect(url_for("activities.view_activity", activity_id=activity_id))

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        activity_type = request.form.get("type", "").strip()
        location = request.form.get("location", "").strip()
        event_date = request.form.get("event_date", "").strip()

        if not title or not activity_type or not location or not event_date:
            flash("Please fill in all required fields.", "danger")
            return render_template("activities/edit.html", activity=activity)

        attachment_filename = activity["attachment"]
        file = request.files.get("attachment")

        if file and file.filename:
            if not allowed_file(file.filename, ALLOWED_EXTENSIONS):
                flash("Invalid file type.", "danger")
                return render_template("activities/edit.html", activity=activity)

            from app import app
            filename = secure_filename(file.filename)
            ext = filename.rsplit(".", 1)[1].lower()
            new_name = f"{uuid.uuid4().hex}.{ext}"
            save_path = os.path.join(app.config["UPLOAD_FOLDER"], new_name)
            file.save(save_path)
            attachment_filename = new_name

        db.query(
            "UPDATE activities SET title=?, description=?, type=?, location=?, event_date=?, attachment=? WHERE id=?",
            (title, description, activity_type, location, event_date, attachment_filename, activity_id)
        )
        
        session.pop("activities_unlocked", None)
        flash("Activity updated successfully.", "success")
        return redirect(url_for("activities.view_activity", activity_id=activity_id))

    return render_template("activities/edit.html", activity=activity)

@activities_bp.route("/activities/<int:activity_id>/delete", methods=["GET", "POST"])
@login_required
def delete_activity(activity_id):
    db = get_db()
    activity = db.query("SELECT * FROM activities WHERE id = ?", (activity_id,), one=True)

    if not activity:
        return "Activity not found", 404

    if int(activity["organizer_id"]) != int(session["user_id"]):
        flash("You are not authorized to delete this activity.", "danger")
        return redirect(url_for("activities.view_activity", activity_id=activity_id))

    if request.method == "POST":
        # Extra security: require password again for deletion
        pwd = request.form.get("password", "")
        pwd_hash = db.get_setting("activities_password_hash")

        if pwd_hash and check_password_hash(pwd_hash, pwd):
            db.query("DELETE FROM activity_rsvps WHERE activity_id = ?", (activity_id,))
            db.query("DELETE FROM activities WHERE id = ?", (activity_id,))
            flash("Activity deleted successfully.", "success")
            return redirect(url_for("activities.activities_list"))
        else:
            flash("Incorrect password.", "danger")

    return render_template("activities/delete_confirm.html", activity=activity)

@activities_bp.route('/activities/<int:activity_id>/join', methods=['POST'])
@login_required
def join_activity(activity_id):
    user_id = session['user_id']
    db = get_db()
    try:
        db.query("INSERT INTO activity_rsvps (activity_id, user_id) VALUES (?, ?)", (activity_id, user_id))
        flash('Successfully joined the activity!', 'success')
        
        # Notify Organizer (if not by themselves)
        activity = db.query("SELECT organizer_id, title FROM activities WHERE id = ?", (activity_id,), one=True)
        if activity and activity['organizer_id'] != user_id:
            sender = db.query("SELECT username FROM users WHERE id = ?", (user_id,), one=True)
            create_notification(
                activity['organizer_id'],
                'Activity',
                f"{sender['username']} joined your activity: {activity['title']}",
                url_for('activities.view_activity', activity_id=activity_id)
            )
    except:
        pass
    return redirect(request.referrer or url_for('activities.activities_list'))

@activities_bp.route('/activities/<int:activity_id>/leave', methods=['POST'])
@login_required
def leave_activity(activity_id):
    user_id = session['user_id']
    db = get_db()
    db.query("DELETE FROM activity_rsvps WHERE activity_id = ? AND user_id = ?", (activity_id, user_id))
    flash('You have left the activity.', 'info')
    return redirect(request.referrer or url_for('activities.activities_list'))

# REPORT ACTIVITY ACTION: Allows users to report an activity
@activities_bp.route('/activities/<int:activity_id>/report', methods=['POST'])
@login_required
def report_activity(activity_id):
    reason = request.form.get('reason')
    if not reason:
        flash('Please provide a reason for reporting.', 'warning')
        return redirect(request.referrer)
        
    db = get_db()
    conn = db.get_connection()
    user_id = session['user_id']
    
    # Check if already reported
    existing = db.query("SELECT id FROM reports WHERE reporter_id = ? AND target_type = 'activity' AND target_id = ?", 
                       (user_id, activity_id), one=True)
    
    if existing:
        flash('You have already reported this activity.', 'info')
    else:
        conn.execute("INSERT INTO reports (reporter_id, target_type, target_id, reason) VALUES (?, 'activity', ?, ?)",
                    (user_id, activity_id, reason))
        conn.commit()
        flash('Activity reported. Thank you for helping keep our community safe.', 'success')
        
    return redirect(request.referrer)

