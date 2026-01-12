from flask import Flask, render_template

app = Flask(__name__)
app.secret_key = 'simple-dashboard-key'

# Mock user data (for demo purposes)
MOCK_USER = {
    'id': 1,
    'username': 'JohnDoe',
    'full_name': 'John Doe',
    'user_type': 'Youth',
    'email': 'john@example.com',
    'profile_pic': 'https://i.pravatar.cc/150?img=1'
}

# Mock statistics
MOCK_STATS = {
    'stories': 5,
    'activities': 3,
    'messages': 12,
    'groups': 2
}

# Mock recent data
MOCK_RECENT_STORIES = [
    {'id': 1, 'title': 'My First Memory', 'author': 'John', 'date': '3 days ago', 'preview': 'Shared a childhood memory about my grandparents...'},
    {'id': 2, 'title': 'Life Lessons', 'author': 'Sarah', 'date': '1 week ago', 'preview': 'Valuable advice from seniors about career choices...'}
]

MOCK_UPCOMING_ACTIVITIES = [
    {'id': 1, 'title': 'Digital Skills Workshop', 'date': 'Tomorrow', 'location': 'Community Center'},
    {'id': 2, 'title': 'Storytelling Session', 'date': 'Next week', 'location': 'Library'}
]

@app.route('/')
def dashboard():
    return render_template('dashboard.html', 
                         user=MOCK_USER,
                         stats=MOCK_STATS,
                         recent_stories=MOCK_RECENT_STORIES,
                         upcoming_activities=MOCK_UPCOMING_ACTIVITIES)

if __name__ == '__main__':
    app.run(debug=True, port=5000)