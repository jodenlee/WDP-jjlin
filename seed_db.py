from database import Database
from models import User, Story, Activity

def seed_data():
    db = Database()
    conn = db.get_connection()
    cursor = conn.cursor()

    # Clear existing data to avoid duplicates if run multiple times
    cursor.execute("DELETE FROM stories")
    cursor.execute("DELETE FROM activities")
    cursor.execute("DELETE FROM users")

    # Create Users
    users = [
        User("grandma_joyce", "senior", "I love knitting and telling stories."),
        User("timmy_turner", "youth", "Student, loves video games and history.")
    ]
    
    user_ids = []
    for user in users:
        cursor.execute("INSERT INTO users (username, role, bio) VALUES (?, ?, ?)", 
                       (user.username, user.role, user.bio))
        user_ids.append(cursor.lastrowid)

    # Create Stories (linked to Senior)
    stories = [
        Story("The Old Oak Tree", "When I was young, we used to swing on the old oak tree...", user_ids[0]),
        Story("My First Car", "It was a bright red convertible from 1955...", user_ids[0])
    ]

    for story in stories:
        cursor.execute("INSERT INTO stories (title, content, author_id) VALUES (?, ?, ?)",
                       (story.title, story.content, story.author_id))

    # Create Activities
    activities = [
        Activity("Sunday Gardening", "Join us in the community garden for some planting.", "Outdoor"),
        Activity("Tech Support Hour", "Youth helping Seniors with their devices.", "Education")
    ]

    for activity in activities:
        cursor.execute("INSERT INTO activities (title, description, type) VALUES (?, ?, ?)",
                       (activity.title, activity.description, activity.activity_type))

    conn.commit()
    conn.close()
    print("Database seeded successfully!")

if __name__ == "__main__":
    seed_data()
