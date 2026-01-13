import unittest
from app import app
from database import Database

class BasicTests(unittest.TestCase):

    def setUp(self):
        app.config['TESTING'] = True
        app.config['DEBUG'] = False
        self.app = app.test_client()
        # Ensure fresh DB state if needed, though seed_db.py should have handled it.
        # For this simple test we rely on what seed_db.py processed.

    def test_main_page(self):
        response = self.app.get('/', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        
        content = response.data.decode('utf-8')
        
        # Check branding
        self.assertIn('TogetherSG', content)
        
        # Check Feature Grid Elements
        self.assertIn('Stories', content)
        self.assertIn('Activities', content)
        self.assertIn('Messages', content)
        self.assertIn('Profile', content)
        self.assertIn('Community', content)

    def test_routes(self):
        # Verify all new routes return 200 OK
        routes = ['/stories', '/activities', '/messages', '/profile', '/community']
        for route in routes:
            response = self.app.get(route, follow_redirects=True)
            self.assertEqual(response.status_code, 200, f"Route {route} failed")

if __name__ == "__main__":
    unittest.main()
