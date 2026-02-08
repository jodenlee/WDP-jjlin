from flask import Flask, g, request
import os
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth
from werkzeug.middleware.proxy_fix import ProxyFix

# Load environment variables from .env file
load_dotenv()

# Global OAuth instance
oauth = OAuth()

def create_app():
    app = Flask(__name__)
    
    # Trust proxy headers (Nginx sends X-Forwarded-Proto, X-Forwarded-Host, etc.)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
    
    app.secret_key = os.environ.get('SECRET_KEY', 'togethersg-secret-key-change-in-production')

    # Google Maps API Key (from environment)
    GOOGLE_MAPS_API_KEY = os.environ.get('GOOGLE_MAPS_API_KEY', '')

    # Upload Configuration
    UPLOAD_FOLDER = os.path.join('static', 'uploads')
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    app.config['ALLOWED_EXTENSIONS'] = ALLOWED_EXTENSIONS
    
    # Force HTTPS for external URL generation (OAuth redirects)
    app.config['PREFERRED_URL_SCHEME'] = 'https'

    # Ensure upload directory exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    # Initialize OAuth with Google
    oauth.init_app(app)
    oauth.register(
        name='google',
        client_id=os.environ.get('GOOGLE_CLIENT_ID', ''),
        client_secret=os.environ.get('GOOGLE_CLIENT_SECRET', ''),
        access_token_url='https://oauth2.googleapis.com/token',
        authorize_url='https://accounts.google.com/o/oauth2/v2/auth',
        api_base_url='https://www.googleapis.com/oauth2/v3/',
        userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
        client_kwargs={'scope': 'openid email profile'},
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    )
    
    # Store oauth on app for access from blueprints
    app.oauth = oauth

    # Initialize Flask-Mail
    try:
        from email_utils import init_mail
        init_mail(app)
    except ImportError:
        pass

    # Inject common variables into all templates
    @app.context_processor
    def inject_globals():
        return {'GOOGLE_MAPS_API_KEY': GOOGLE_MAPS_API_KEY}

    from utils import get_db, get_current_user

    @app.before_request
    def load_logged_in_user():
        g.user = get_current_user()

    @app.teardown_appcontext
    def close_db(error):
        if hasattr(g, 'db'):
            pass

    # Register Blueprints
    from routes.auth import auth_bp
    from routes.stories import stories_bp
    from routes.activities import activities_bp
    from routes.messages import messages_bp
    from routes.main import main_bp
    from routes.community import community_bp
    from routes.admin import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(stories_bp)
    app.register_blueprint(activities_bp)
    app.register_blueprint(messages_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(community_bp)
    app.register_blueprint(admin_bp)

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
