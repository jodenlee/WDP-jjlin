from flask import Flask, g, request
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

def create_app():
    app = Flask(__name__)
    app.secret_key = os.environ.get('SECRET_KEY', 'togethersg-secret-key-change-in-production')

    # Google Maps API Key (from environment)
    GOOGLE_MAPS_API_KEY = os.environ.get('GOOGLE_MAPS_API_KEY', '')

    # Upload Configuration
    UPLOAD_FOLDER = os.path.join('static', 'uploads')
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    app.config['ALLOWED_EXTENSIONS'] = ALLOWED_EXTENSIONS

    # Ensure upload directory exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

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

    app.register_blueprint(auth_bp)
    app.register_blueprint(stories_bp)
    app.register_blueprint(activities_bp)
    app.register_blueprint(messages_bp)
    app.register_blueprint(main_bp)

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
