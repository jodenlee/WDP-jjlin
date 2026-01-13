class User:
    def __init__(self, username, role, bio=""):
        self.username = username
        self.role = role
        self.bio = bio
        self.validate()

    def validate(self):
        if not self.username:
            raise ValueError("Username cannot be empty.")
        if self.role not in ['senior', 'youth']:
            raise ValueError("Role must be either 'senior' or 'youth'.")

class Story:
    def __init__(self, title, content, author_id, location="", image_url="", likes=0):
        self.title = title
        self.content = content
        self.author_id = author_id
        self.location = location
        self.image_url = image_url
        self.likes = likes
        self.validate()

    def validate(self):
        if not self.title:
            raise ValueError("Story title cannot be empty.")
        if not self.content:
            raise ValueError("Story content cannot be empty.")

class Activity:
    def __init__(self, title, description, activity_type):
        self.title = title
        self.description = description
        self.activity_type = activity_type
        self.validate()

    def validate(self):
        if not self.title:
            raise ValueError("Activity title cannot be empty.")
        if not self.description:
            raise ValueError("Activity description cannot be empty.")
