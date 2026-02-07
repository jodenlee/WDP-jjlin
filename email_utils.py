# Email Utilities for OTP verification
import random
import string
from datetime import datetime, timedelta
from flask_mail import Mail, Message
from flask import current_app

mail = Mail()

def init_mail(app):
    """Initialize Flask-Mail with Gmail SMTP configuration"""
    # Configure Gmail SMTP - USER MUST SET THESE ENVIRONMENT VARIABLES
    import os
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', '')
    app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', '')
    app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME', '')
    
    mail.init_app(app)
    return mail

def generate_otp(length=6):
    """Generate a random numeric OTP code"""
    return ''.join(random.choices(string.digits, k=length))

def get_otp_expiry(minutes=5):
    """Get expiry timestamp for OTP (default 5 minutes)"""
    return datetime.now() + timedelta(minutes=minutes)

def send_verification_email(to_email, otp_code, purpose='registration'):
    """Send OTP verification email"""
    try:
        if purpose == 'registration':
            subject = 'TogetherSG - Verify Your Email'
            body = f'''
Welcome to TogetherSG!

Your email verification code is: {otp_code}

This code will expire in 5 minutes.

If you did not create an account, please ignore this email.

Best regards,
TogetherSG Team
'''
        else:  # login
            subject = 'TogetherSG - Login Verification Code'
            body = f'''
Hello!

Your login verification code is: {otp_code}

This code will expire in 5 minutes.

If you did not attempt to log in, please secure your account immediately.

Best regards,
TogetherSG Team
'''
        
        msg = Message(
            subject=subject,
            recipients=[to_email],
            body=body
        )
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False
