from flask import Flask, render_template, g
from database import Database

app = Flask(__name__)

# Database Helper to get db connection per request
def get_db():
    if 'db' not in g:
        g.db = Database()
    return g.db

@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'db'):
        # In this simple implementation, Database class opens connection on every query
        # so we might not need to strictly close the object itself if it doesn't hold a persistent connection
        # But for good practice if we changed implementation:
        pass

@app.route('/')
def dashboard():
    # Initialize DB (creates tables if not exist)
    db = get_db()
    
    # Fetch some sample data to display
    # This is where we would fetch latest stories and activities
    recent_stories = db.query("SELECT * FROM stories ORDER BY created_at DESC LIMIT 3")
    upcoming_activities = db.query("SELECT * FROM activities ORDER BY created_at DESC LIMIT 3")
    
    return render_template('index.html', stories=recent_stories, activities=upcoming_activities)

@app.route('/stories')
def stories():
    return render_template('index.html', stories=[], activities=[]) # Placeholder

@app.route('/activities')
def activities():
    return render_template('index.html', stories=[], activities=[]) # Placeholder

@app.route('/messages')
def messages():
    return render_template('index.html', stories=[], activities=[]) # Placeholder

@app.route('/profile')
def profile():
    return render_template('index.html', stories=[], activities=[]) # Placeholder

@app.route('/community')
def community():
    return render_template('index.html', stories=[], activities=[]) # Placeholder

if __name__ == '__main__':
    app.run(debug=True)
