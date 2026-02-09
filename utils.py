from flask import g, session, flash, redirect, url_for
from functools import wraps
from database import Database
import os

# Database Helper to get db connection per request
def get_db():
    if 'db' not in g:
        g.db = Database()
    return g.db

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

# Get current user helper
def get_current_user():
    if 'user_id' in session:
        db = get_db()
        return db.query("SELECT * FROM users WHERE id = ?", (session['user_id'],), one=True)
    return None

def allowed_file(filename, allowed_extensions):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in allowed_extensions

# OpenAI Content Moderation Helper
def check_content_moderation(text):
    """
    Checks text content against OpenAI's moderation API.
    Returns True if content is flagged as harmful, False otherwise.
    """
    from openai import OpenAI
    from dotenv import load_dotenv
    
    load_dotenv()
    api_key = os.getenv('OPENAI_API_KEY')
    print(f"DEBUG: Moderation API Key found: {'Yes' if api_key else 'No'}")
    
    if not api_key or not text:
        if not api_key:
            print("DEBUG: Moderation API Key is MISSING in environment.")
        return False  # Fail open if no API key or empty text
    
    try:
        client = OpenAI(api_key=api_key)
        print(f"DEBUG: Sending moderation request for: {text[:20]}...")
        response = client.moderations.create(input=text)
        is_flagged = response.results[0].flagged
        print(f"DEBUG: Moderation result: flagged={is_flagged}")
        return is_flagged
    except Exception as e:
        print(f"DEBUG: Moderation API error: {e}")
        return False


def auto_translate(text, target_lang=None):
    """
    Automated translation with local caching.
    """
    from flask import g
    from google.cloud import translate_v2 as translate
    import html

    if not text or not text.strip():
        return text

    # If target_lang not specified, get from g.user or default to en
    if not target_lang:
        target_lang = 'en'
        if hasattr(g, 'user') and g.user and 'language' in g.user.keys():
            target_lang = g.user['language']
    

    # For English, just return original text
    if target_lang == 'en':
        return text

    # Normalise language code for Google/Cache
    if target_lang == 'zh_CN':
        target_lang = 'zh-CN'

    db = get_db()
    
    # Check cache
    cache = db.query("SELECT translation FROM ui_translations WHERE text_key = ? AND language = ?", (text, target_lang), one=True)
    if cache:
        return cache['translation']

    # Translate using Google API
    try:
        import requests
        api_key = os.environ.get('GOOGLE_MAPS_API_KEY')
        if not api_key:
            return text
            
        url = f"https://translation.googleapis.com/language/translate/v2?key={api_key}"
        payload = {
            "q": text,
            "target": target_lang,
            "format": "text" # Use text format to avoid excessive escaping
        }
        
        response = requests.post(url, json=payload)
        response_data = response.json()
        
        if 'data' in response_data and 'translations' in response_data['data']:
            translated_text = html.unescape(response_data['data']['translations'][0]['translatedText'])
            
            # Save to cache
            conn = db.get_connection()
            conn.execute("INSERT OR REPLACE INTO ui_translations (text_key, language, translation) VALUES (?, ?, ?)", 
                         (text, target_lang, translated_text))
            conn.commit()
            
            return translated_text
        else:
            return text
            
    except Exception as e:
        return text

def translate_text(text, target_lang='en'):
    """
    Translates text using Google Cloud Translation REST API.
    """
    import os
    import requests
    import html
    
    if not text:
        return ""
        
    try:
        api_key = os.environ.get('GOOGLE_MAPS_API_KEY')
        if not api_key:
            return text
            
        # Normalize language codes for Google
        if target_lang == 'zh_CN':
            target_lang = 'zh-CN'
            
        url = f"https://translation.googleapis.com/language/translate/v2?key={api_key}"
        payload = {
            "q": text,
            "target": target_lang
        }
        
        response = requests.post(url, json=payload)
        response_data = response.json()
        
        if 'data' in response_data and 'translations' in response_data['data']:
            return html.unescape(response_data['data']['translations'][0]['translatedText'])
        return text
            
    except Exception as e:
        return text  # Fallback to original text
