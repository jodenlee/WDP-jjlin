from flask import Blueprint, request, jsonify
from utils import translate_text, login_required

translate_bp = Blueprint('translate', __name__)

@translate_bp.route('/translate', methods=['POST'])
@login_required
def translate():
    """
    API endpoint to translate text dynamically.
    Expects JSON: { "text": "...", "target_lang": "..." }
    """
    data = request.get_json()
    
    if not data or 'text' not in data:
        return jsonify({'error': 'No text provided'}), 400
        
    text = data.get('text')
    target_lang = data.get('target_lang')
    
    from utils import auto_translate
    translated_text = auto_translate(text, target_lang)
    
    return jsonify({
        'original_text': text,
        'translated_text': translated_text,
        'target_lang': target_lang
    })
