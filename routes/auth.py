from flask import Blueprint, render_template, request, redirect, url_for, session, flash, g, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from utils import get_db, login_required
from datetime import datetime, timedelta
import re
import os

auth_bp = Blueprint('auth', __name__)

# Import email utilities
try:
    from email_utils import generate_otp, get_otp_expiry, send_verification_email
except ImportError:
    # Fallback if email_utils not available
    def generate_otp(length=6):
        import random, string
        return ''.join(random.choices(string.digits, k=length))
    def get_otp_expiry(minutes=5):
        return datetime.now() + timedelta(minutes=minutes)
    def send_verification_email(to_email, otp_code, purpose='registration'):
        print(f"[EMAIL] Would send {purpose} OTP {otp_code} to {to_email}")
        return True

# ============================================================================
# LOGIN ROUTE
# ============================================================================
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('main.home'))
    
    error = None
    success = request.args.get('success')
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        
        if not email or not password:
            error = 'Please enter both email and password.'
        else:
            db = get_db()
            user = db.query("SELECT * FROM users WHERE email = ?", (email,), one=True)
            
            if user and user['password_hash'] and check_password_hash(user['password_hash'], password):
                # Check if email is verified
                try:
                    is_verified = user['is_verified']
                except (KeyError, IndexError):
                    is_verified = 1  # Default to verified for older accounts
                
                if not is_verified:
                    session['pending_verification_email'] = email
                    flash('Please verify your email first.', 'warning')
                    return redirect(url_for('auth.verify_email'))
                
                # Check if user is admin - skip OTP for admin
                try:
                    if user['is_admin']:
                        session['user_id'] = user['id']
                        session['username'] = user['username']
                        flash('Welcome back, Admin!', 'success')
                        return redirect(url_for('admin.admin_dashboard'))
                except (KeyError, IndexError):
                    pass
                
                # Check for trusted device
                device_token = request.cookies.get('trusted_device')
                if device_token:
                    trusted = db.query(
                        """SELECT * FROM trusted_devices 
                           WHERE user_id = ? AND device_token = ? AND expires_at > ?""",
                        (user['id'], device_token, datetime.now()), one=True
                    )
                    if trusted:
                        session['user_id'] = user['id']
                        session['username'] = user['username']
                        try:
                            if user['language']:
                                session['language'] = user['language']
                        except (KeyError, IndexError):
                            pass
                        flash('Welcome back!', 'success')
                        return redirect(url_for('main.home'))
                
                # Regular user - generate login OTP
                otp_code = generate_otp()
                expires_at = get_otp_expiry()
                
                conn = db.get_connection()
                conn.execute(
                    """INSERT INTO login_otps (user_id, email, code, expires_at) 
                       VALUES (?, ?, ?, ?)""",
                    (user['id'], email, otp_code, expires_at)
                )
                conn.commit()
                conn.close()
                
                # Send OTP email
                email_sent = send_verification_email(email, otp_code, purpose='login')
                
                session['pending_login_user_id'] = user['id']
                session['pending_login_email'] = email
                
                if email_sent:
                    flash('Please check your email for the login verification code.', 'info')
                else:
                    flash('Could not send verification code. Please try again.', 'warning')
                
                return redirect(url_for('auth.verify_login_otp'))
            else:
                error = 'Invalid email or password.'
    
    return render_template('auth/login.html', error=error, success=success)

# ============================================================================
# GOOGLE OAUTH ROUTES
# ============================================================================
@auth_bp.route('/auth/google')
def google_login():
    """Initiate Google OAuth login flow"""
    try:
        google = current_app.oauth.google
        redirect_uri = url_for('auth.google_callback', _external=True)
        return google.authorize_redirect(redirect_uri)
    except Exception as e:
        print(f"Google OAuth error: {e}")
        flash('Google login is not configured.', 'danger')
        return redirect(url_for('auth.login'))

@auth_bp.route('/auth/google/callback')
def google_callback():
    """Handle Google OAuth callback"""
    try:
        google = current_app.oauth.google
        token = google.authorize_access_token()
        user_info = token.get('userinfo')
        
        if not user_info:
            flash('Could not get user info from Google.', 'danger')
            return redirect(url_for('auth.login'))
        
        email = user_info.get('email', '').lower()
        name = user_info.get('name', '')
        
        if not email:
            flash('Could not get email from Google account.', 'danger')
            return redirect(url_for('auth.login'))
        
        db = get_db()
        user = db.query("SELECT * FROM users WHERE email = ?", (email,), one=True)
        
        if not user:
            # Create new user from Google account
            username = email.split('@')[0].lower()
            existing = db.query("SELECT id FROM users WHERE username = ?", (username,), one=True)
            if existing:
                import time
                username = f"{username}_{int(time.time()) % 10000}"
            
            conn = db.get_connection()
            conn.execute(
                """INSERT INTO users (username, email, password_hash, role, full_name, is_verified) 
                   VALUES (?, ?, ?, ?, ?, 1)""",
                (username, email, '', 'youth', name)
            )
            conn.commit()
            conn.close()
            user = db.query("SELECT * FROM users WHERE email = ?", (email,), one=True)
        
        # Generate login OTP
        otp_code = generate_otp()
        expires_at = get_otp_expiry()
        
        conn = db.get_connection()
        conn.execute(
            """INSERT INTO login_otps (user_id, email, code, expires_at) 
               VALUES (?, ?, ?, ?)""",
            (user['id'], email, otp_code, expires_at)
        )
        conn.commit()
        conn.close()
        
        email_sent = send_verification_email(email, otp_code, purpose='login')
        
        session['pending_login_user_id'] = user['id']
        session['pending_login_email'] = email
        
        if email_sent:
            flash('Please check your email for the login verification code.', 'info')
        else:
            flash('Could not send verification code. Please try again.', 'warning')
        
        return redirect(url_for('auth.verify_login_otp'))
        
    except Exception as e:
        print(f"Google OAuth error: {e}")
        flash('Google login failed. Please try again.', 'danger')
        return redirect(url_for('auth.login'))

# ============================================================================
# REGISTER ROUTE
# ============================================================================
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('main.home'))
    
    errors = []
    form = {}
    
    if request.method == 'POST':
        form['full_name'] = request.form.get('full_name', '').strip()
        form['username'] = request.form.get('username', '').strip().lower()
        form['email'] = request.form.get('email', '').strip().lower()
        form['role'] = request.form.get('role', 'youth')
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        terms = request.form.get('terms')
        
        # Validation
        if not form['full_name']:
            errors.append('Full name is required.')
        
        if not form['username']:
            errors.append('Username is required.')
        elif not re.match(r'^[a-zA-Z0-9_]{3,20}$', form['username']):
            errors.append('Username must be 3-20 characters, letters, numbers, and underscores only.')
        
        if not form['email']:
            errors.append('Email is required.')
        elif not re.match(r'^[a-zA-Z0-9._%+-]+@gmail\.com$', form['email']):
            errors.append('Please use a Gmail address (@gmail.com) to register.')
        
        if not password:
            errors.append('Password is required.')
        elif len(password) < 6:
            errors.append('Password must be at least 6 characters.')
        elif not re.search(r'[A-Z]', password):
            errors.append('Password must contain at least one capital letter.')
        elif not re.search(r'[0-9]', password):
            errors.append('Password must contain at least one number.')
        
        if password != confirm_password:
            errors.append('Passwords do not match.')
        
        if not terms:
            errors.append('You must agree to the terms.')
        
        # Check if username or email already exists
        if not errors:
            db = get_db()
            existing_user = db.query("SELECT * FROM users WHERE username = ? OR email = ?", 
                                     (form['username'], form['email']), one=True)
            if existing_user:
                if existing_user['username'] == form['username']:
                    errors.append('Username already taken.')
                if existing_user['email'] == form['email']:
                    errors.append('Email already registered.')
        
        # Create user if no errors (with is_verified=0)
        if not errors:
            password_hash = generate_password_hash(password)
            db = get_db()
            conn = db.get_connection()
            try:
                conn.execute(
                    """INSERT INTO users (username, email, password_hash, role, full_name, is_verified) 
                       VALUES (?, ?, ?, ?, ?, 0)""",
                    (form['username'], form['email'], password_hash, form['role'], form['full_name'])
                )
                conn.commit()
                
                # Generate OTP
                otp_code = generate_otp()
                expires_at = get_otp_expiry()
                conn.execute(
                    """INSERT INTO email_verifications (email, code, expires_at) 
                       VALUES (?, ?, ?)""",
                    (form['email'], otp_code, expires_at)
                )
                conn.commit()
                conn.close()
                
                email_sent = send_verification_email(form['email'], otp_code, purpose='registration')
                session['pending_verification_email'] = form['email']
                
                if email_sent:
                    flash('Please check your email for the verification code.', 'info')
                else:
                    flash('Account created but verification email failed. Please try resending.', 'warning')
                
                return redirect(url_for('auth.verify_email'))
            except Exception as e:
                print(f"Registration error: {e}")
                errors.append('An error occurred. Please try again.')
    
    return render_template('auth/register.html', errors=errors, form=form)

# ============================================================================
# EMAIL VERIFICATION ROUTES
# ============================================================================
@auth_bp.route('/verify-email', methods=['GET', 'POST'])
def verify_email():
    email = session.get('pending_verification_email')
    if not email:
        flash('No pending verification. Please register first.', 'warning')
        return redirect(url_for('auth.register'))
    
    error = None
    
    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        
        if not code:
            error = 'Please enter the verification code.'
        else:
            db = get_db()
            verification = db.query(
                """SELECT * FROM email_verifications 
                   WHERE email = ? AND code = ? AND is_used = 0 AND expires_at > ?
                   ORDER BY created_at DESC LIMIT 1""",
                (email, code, datetime.now()), one=True
            )
            
            if verification:
                conn = db.get_connection()
                conn.execute("UPDATE email_verifications SET is_used = 1 WHERE id = ?", (verification['id'],))
                conn.execute("UPDATE users SET is_verified = 1 WHERE email = ?", (email,))
                conn.commit()
                conn.close()
                
                session.pop('pending_verification_email', None)
                flash('Email verified successfully! You can now log in.', 'success')
                return redirect(url_for('auth.login'))
            else:
                error = 'Invalid or expired verification code. Please try again or request a new code.'
    
    return render_template('auth/verify_email.html', email=email, error=error)

@auth_bp.route('/resend-verification', methods=['POST'])
def resend_verification():
    email = session.get('pending_verification_email')
    if not email:
        flash('No pending verification.', 'warning')
        return redirect(url_for('auth.register'))
    
    otp_code = generate_otp()
    expires_at = get_otp_expiry()
    
    db = get_db()
    conn = db.get_connection()
    conn.execute(
        """INSERT INTO email_verifications (email, code, expires_at) 
           VALUES (?, ?, ?)""",
        (email, otp_code, expires_at)
    )
    conn.commit()
    conn.close()
    
    email_sent = send_verification_email(email, otp_code, purpose='registration')
    
    if email_sent:
        flash('New verification code sent to your email.', 'success')
    else:
        flash('Could not send verification code. Please try again.', 'danger')
    
    return redirect(url_for('auth.verify_email'))

# ============================================================================
# LOGIN OTP VERIFICATION ROUTES
# ============================================================================
@auth_bp.route('/verify-login-otp', methods=['GET', 'POST'])
def verify_login_otp():
    user_id = session.get('pending_login_user_id')
    email = session.get('pending_login_email')
    
    if not user_id or not email:
        flash('Please log in first.', 'warning')
        return redirect(url_for('auth.login'))
    
    error = None
    
    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        
        if not code:
            error = 'Please enter the verification code.'
        else:
            db = get_db()
            otp_record = db.query(
                """SELECT * FROM login_otps 
                   WHERE user_id = ? AND code = ? AND is_used = 0 AND expires_at > ?
                   ORDER BY created_at DESC LIMIT 1""",
                (user_id, code, datetime.now()), one=True
            )
            
            if otp_record:
                conn = db.get_connection()
                conn.execute("UPDATE login_otps SET is_used = 1 WHERE id = ?", (otp_record['id'],))
                conn.commit()
                conn.close()
                
                user = db.query("SELECT * FROM users WHERE id = ?", (user_id,), one=True)
                
                session['user_id'] = user['id']
                session['username'] = user['username']
                
                try:
                    if user['language']:
                        session['language'] = user['language']
                except (KeyError, IndexError):
                    pass
                
                session.pop('pending_login_user_id', None)
                session.pop('pending_login_email', None)
                
                flash('Welcome back!', 'success')
                
                try:
                    if user['is_admin']:
                        response = redirect(url_for('admin.admin_dashboard'))
                    else:
                        response = redirect(url_for('main.home'))
                except (KeyError, IndexError):
                    response = redirect(url_for('main.home'))
                
                # Handle trust device checkbox
                trust_device = request.form.get('trust_device')
                if trust_device:
                    import secrets
                    device_token = secrets.token_urlsafe(32)
                    expires_at = datetime.now() + timedelta(days=30)
                    
                    conn = db.get_connection()
                    conn.execute(
                        """INSERT INTO trusted_devices (user_id, device_token, expires_at) 
                           VALUES (?, ?, ?)""",
                        (user['id'], device_token, expires_at)
                    )
                    conn.commit()
                    conn.close()
                    
                    response.set_cookie('trusted_device', device_token, max_age=30*24*60*60, httponly=True)
                
                return response
            else:
                error = 'Invalid or expired code. Please try again or request a new code.'
    
    return render_template('auth/verify_login_otp.html', email=email, error=error)

@auth_bp.route('/resend-login-otp', methods=['POST'])
def resend_login_otp():
    user_id = session.get('pending_login_user_id')
    email = session.get('pending_login_email')
    
    if not user_id or not email:
        flash('Please log in first.', 'warning')
        return redirect(url_for('auth.login'))
    
    otp_code = generate_otp()
    expires_at = get_otp_expiry()
    
    db = get_db()
    conn = db.get_connection()
    conn.execute(
        """INSERT INTO login_otps (user_id, email, code, expires_at) 
           VALUES (?, ?, ?, ?)""",
        (user_id, email, otp_code, expires_at)
    )
    conn.commit()
    conn.close()
    
    email_sent = send_verification_email(email, otp_code, purpose='login')
    
    if email_sent:
        flash('New verification code sent to your email.', 'success')
    else:
        flash('Could not send verification code. Please try again.', 'danger')
    
    return redirect(url_for('auth.verify_login_otp'))

# ============================================================================
# PASSWORD RESET ROUTES
# ============================================================================
@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    error = None
    if request.method == 'POST':
        email = request.form['email']
        db = get_db()
        user = db.query("SELECT * FROM users WHERE email = ?", (email,), one=True)
        
        if user:
            token = f"reset_{user['id']}"
            return redirect(url_for('auth.reset_password', token=token, email=email))
        else:
            error = "Invalid email. No account found with this email address."
            
    return render_template('auth/forgot_password.html', error=error)

@auth_bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    email = request.args.get('email')
    
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if len(password) < 6:
            flash('Password must be at least 6 characters.', 'danger')
            return render_template('auth/reset_password.html', token=token, email=email)
        
        if not re.search(r'[A-Z]', password):
            flash('Password must contain at least one capital letter.', 'danger')
            return render_template('auth/reset_password.html', token=token, email=email)
        
        if not re.search(r'[0-9]', password):
            flash('Password must contain at least one number.', 'danger')
            return render_template('auth/reset_password.html', token=token, email=email)
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('auth/reset_password.html', token=token, email=email)
            
        if email:
            db = get_db()
            conn = db.get_connection()
            new_hash = generate_password_hash(password)
            conn.execute("UPDATE users SET password_hash = ? WHERE email = ?", (new_hash, email))
            conn.commit()
            
            flash('Password has been reset successfully. Please login.', 'success')
            return redirect(url_for('auth.login'))
        else:
             flash('Invalid link.', 'danger')
             return redirect(url_for('auth.login'))
             
    return render_template('auth/reset_password.html', token=token, email=email)

@auth_bp.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        user_id = session['user_id']
        db = get_db()
        user = db.query("SELECT * FROM users WHERE id = ?", (user_id,), one=True)
        
        if not check_password_hash(user['password_hash'], current_password):
            flash('Current password is incorrect.', 'danger')
            return render_template('auth/change_password.html')
        
        if len(new_password) < 6:
            flash('New password must be at least 6 characters.', 'danger')
            return render_template('auth/change_password.html')
        
        if not re.search(r'[A-Z]', new_password):
            flash('New password must contain at least one capital letter.', 'danger')
            return render_template('auth/change_password.html')
        
        if not re.search(r'[0-9]', new_password):
            flash('New password must contain at least one number.', 'danger')
            return render_template('auth/change_password.html')
        
        if new_password != confirm_password:
            flash('New passwords do not match.', 'danger')
            return render_template('auth/change_password.html')
        
        conn = db.get_connection()
        new_hash = generate_password_hash(new_password)
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user_id))
        conn.commit()
        
        flash('Password changed successfully!', 'success')
        return redirect(url_for('auth.profile'))
        
    return render_template('auth/change_password.html')

# ============================================================================
# LOGOUT ROUTE
# ============================================================================
@auth_bp.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))

# ============================================================================
# PROFILE ROUTES
# ============================================================================
@auth_bp.route('/profile')
@login_required
def profile():
    db = get_db()
    user_id = session['user_id']
    
    user_data = db.query("SELECT * FROM users WHERE id = ?", (user_id,), one=True)
    
    if user_data:
        try:
            if user_data['language']:
                session['language'] = user_data['language']
        except (KeyError, IndexError):
            pass
        
        try:
            user_language = user_data['language'] or 'en'
        except (KeyError, IndexError):
            user_language = 'en'
        
        try:
            notify_messages = user_data['notify_messages']
            notify_activities = user_data['notify_activities']
            notify_stories = user_data['notify_stories']
            notify_groups = user_data['notify_groups']
        except (KeyError, IndexError):
            notify_messages = notify_activities = notify_stories = notify_groups = 1
        
        user = {
            'id': user_data['id'],
            'full_name': user_data['full_name'] or user_data['username'],
            'username': user_data['username'],
            'user_type': user_data['role'].capitalize(),
            'bio': user_data['bio'],
            'profile_pic': user_data['profile_pic'] or f"https://ui-avatars.com/api/?name={user_data['username']}&background=8D6E63&color=fff",
            'language': user_language,
            'notify_messages': notify_messages,
            'notify_activities': notify_activities,
            'notify_stories': notify_stories,
            'notify_groups': notify_groups
        }
    else:
        return redirect(url_for('auth.logout'))
    
    return render_template('profile.html', user=user)

@auth_bp.route('/profile/update', methods=['POST'])
@login_required
def update_profile():
    user_id = session['user_id']
    full_name = request.form.get('full_name', '')
    bio = request.form.get('bio', '')
    
    # Handle Profile Pic Upload
    from werkzeug.utils import secure_filename
    UPLOAD_FOLDER = os.path.join('static', 'uploads')
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
    
    def allowed_file(filename):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
    
    profile_pic = request.files.get('profile_pic')
    profile_pic_path = None
    
    if profile_pic and allowed_file(profile_pic.filename):
        filename = secure_filename(profile_pic.filename)
        import time
        filename = f"profile_{user_id}_{int(time.time())}_{filename}"
        filepath = os.path.join(UPLOAD_FOLDER, 'profile_pics')
        os.makedirs(filepath, exist_ok=True)
        full_path = os.path.join(filepath, filename)
        profile_pic.save(full_path)
        profile_pic_path = f"uploads/profile_pics/{filename}"
    
    # Notification Settings
    notify_messages = 1 if 'notify_messages' in request.form else 0
    notify_activities = 1 if 'notify_activities' in request.form else 0
    notify_stories = 1 if 'notify_stories' in request.form else 0
    notify_groups = 1 if 'notify_groups' in request.form else 0

    db = get_db()
    conn = db.get_connection()
    
    query = "UPDATE users SET full_name = ?, bio = ?, notify_messages = ?, notify_activities = ?, notify_stories = ?, notify_groups = ?"
    params = [full_name, bio, notify_messages, notify_activities, notify_stories, notify_groups]
    
    if profile_pic_path:
        query += ", profile_pic = ?"
        params.append(request.url_root + 'static/' + profile_pic_path)
        
    query += " WHERE id = ?"
    params.append(user_id)
    
    conn.execute(query, params)
    conn.commit()
    
    return redirect(url_for('auth.profile'))

@auth_bp.route('/profile/update_notifications', methods=['POST'])
@login_required
def update_notifications():
    user_id = session['user_id']
    
    notify_messages = 1 if 'notify_messages' in request.form else 0
    notify_activities = 1 if 'notify_activities' in request.form else 0
    notify_stories = 1 if 'notify_stories' in request.form else 0
    notify_groups = 1 if 'notify_groups' in request.form else 0

    db = get_db()
    conn = db.get_connection()
    
    conn.execute("""
        UPDATE users 
        SET notify_messages = ?, notify_activities = ?, notify_stories = ?, notify_groups = ?
        WHERE id = ?
    """, (notify_messages, notify_activities, notify_stories, notify_groups, user_id))
    conn.commit()
    
    return redirect(url_for('auth.profile'))

@auth_bp.route('/profile/delete', methods=['POST'])
@login_required
def delete_account():
    user_id = session['user_id']

    db = get_db()
    conn = db.get_connection()
    
    # Delete user's bookmarks
    conn.execute("DELETE FROM bookmarks WHERE user_id = ?", (user_id,))
    # Delete user's likes
    conn.execute("DELETE FROM story_likes WHERE user_id = ?", (user_id,))
    # Delete user's comments
    conn.execute("DELETE FROM comments WHERE user_id = ?", (user_id,))
    # Delete user's stories
    conn.execute("DELETE FROM stories WHERE author_id = ?", (user_id,))
    # Delete activity RSVPs
    conn.execute("DELETE FROM activity_rsvps WHERE user_id = ?", (user_id,))
    # Delete messages
    conn.execute("DELETE FROM messages WHERE sender_id = ? OR receiver_id = ?", (user_id, user_id))
    # Delete notifications
    conn.execute("DELETE FROM notifications WHERE user_id = ?", (user_id,))
    # Delete trusted devices
    conn.execute("DELETE FROM trusted_devices WHERE user_id = ?", (user_id,))
    # Finally delete the user
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    
    conn.commit()
    session.clear()
    flash('Your account has been permanently deleted.', 'info')
    return redirect(url_for('auth.login'))

# ============================================================================
# NOTIFICATION ROUTES
# ============================================================================
@auth_bp.route('/notifications/mark_read/<int:notif_id>', methods=['POST'])
@login_required
def mark_notification_read(notif_id):
    db = get_db()
    conn = db.get_connection()
    conn.execute("UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?", (notif_id, session['user_id']))
    conn.commit()
    return "OK", 200

@auth_bp.route('/notifications/clear_all', methods=['POST'])
@login_required
def clear_all_notifications():
    db = get_db()
    conn = db.get_connection()
    conn.execute("UPDATE notifications SET is_read = 1 WHERE user_id = ?", (session['user_id'],))
    conn.commit()
    return redirect(request.referrer)
