from flask import Blueprint, render_template
from utils import get_db

main_bp = Blueprint('main', __name__)

# MAIN HOME ROUTE: Fetches recent stories and upcoming activities for the landing page
@main_bp.route('/')
def home():
    db = get_db()
    
    # Fetch content for the public homepage (for both guests and logged-in users)
    recent_stories = db.query("SELECT * FROM stories ORDER BY created_at DESC LIMIT 3")
    upcoming_activities = db.query("SELECT * FROM activities ORDER BY created_at DESC LIMIT 3")
    
    return render_template('index.html', stories=recent_stories, activities=upcoming_activities)
