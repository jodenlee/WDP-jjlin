from flask import Blueprint, render_template, request, redirect, url_for, session, flash, current_app, jsonify
from werkzeug.utils import secure_filename
from utils import get_db, login_required, allowed_file, check_content_moderation, create_notification
import os
import time
import math
from google import genai
from google.cloud import storage
from dotenv import load_dotenv

load_dotenv()

# Configure Gemini API
GENAI_API_KEY = os.getenv('GOOGLE_MAPS_API_KEY') # User put it here based on previous turn, actually distinct key usually but let's check
# Wait, the user said they added "gemini api key". I should use 'GEMINI_API_KEY'
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')

client = None
if GEMINI_API_KEY:
    try:
        client = genai.Client(api_key=GEMINI_API_KEY)
    except Exception as e:
        print(f"Error initializing Gemini client: {e}")


def get_location_insight(location):
    if not client or not location:
        return None
    
    try:
        prompt = f"Tell me a real short and interesting fact about {location}, Singapore in 2-3 sentences."
        response = client.models.generate_content(
            model='gemini-2.0-flash', 
            contents=prompt
        )
        return response.text
    except Exception as e:
        print(f"Error fetching AI insight: {e}")
        return None


def upload_to_gcs(file_obj, filename):
    """Uploads a file to Google Cloud Storage and returns the public URL."""
    bucket_name = os.getenv('GCS_BUCKET_NAME')
    if not bucket_name:
        print("GCS_BUCKET_NAME not set in environment.")
        return None
    
    try:
        storage_client = storage.Client()
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(f"uploads/{filename}")
        
        # Upload from the file object
        blob.upload_from_file(file_obj, content_type=file_obj.content_type)
        
        # Make the blob public (optional, depends on bucket settings)
        # blob.make_public() 
        
        return blob.public_url
    except Exception as e:
        print(f"Error uploading to GCS: {e}")
        return None


stories_bp = Blueprint('stories', __name__)

# STORY LIST VIEW: Retrieves all stories with optional filtering (search, location, tags) and sorting (newest, popular)
@stories_bp.route('/stories')
def stories_list():
    db = get_db()
    
    # Get parameters
    search = request.args.get('search', '')
    sort = request.args.get('sort', 'newest')
    location_filter = request.args.get('location', '')
    tags_filter = request.args.getlist('tags')  # Multiple tags can be selected
    
    # Build Query
    query = "SELECT DISTINCT s.*, u.username, u.profile_pic FROM stories s LEFT JOIN users u ON s.author_id = u.id"
    args = []
    
    # FILTER BY TAGS: Join with story_tags if tags filter is applied
    if tags_filter:
        placeholders = ','.join(['?' for _ in tags_filter])
        query += f" INNER JOIN story_tags st ON s.id = st.story_id AND st.tag IN ({placeholders})"
        args.extend(tags_filter)
    
    query += " WHERE 1=1"
    
    if search:
        query += " AND (s.title LIKE ? OR s.content LIKE ?)"
        args.extend([f'%{search}%', f'%{search}%'])
        
    if location_filter:
        query += " AND s.location LIKE ?"
        args.append(f'%{location_filter}%')
        
    if sort == 'likes':
        query += " ORDER BY s.likes DESC"
    else:
        query += " ORDER BY s.created_at DESC"
        
    # Pagination
    page = request.args.get('page', 1, type=int)
    per_page = 6
    offset = (page - 1) * per_page
    
    # Get Total Count first
    count_query = query.replace("SELECT DISTINCT s.*", "SELECT COUNT(DISTINCT s.id)")
    total_stories = db.query(count_query, args, one=True)['COUNT(DISTINCT s.id)']
    total_pages = math.ceil(total_stories / per_page)
    
    # Apply Limit/Offset to main query
    query += " LIMIT ? OFFSET ?"
    args.extend([per_page, offset])
    
    stories_data = db.query(query, args)
    
    # Get user's bookmarks and likes if logged in
    bookmarked_story_ids = []
    liked_story_ids = []
    
    if 'user_id' in session:
        user_id = session['user_id']
        bookmarks = db.query("SELECT story_id FROM bookmarks WHERE user_id = ?", (user_id,))
        bookmarked_story_ids = [b['story_id'] for b in bookmarks]
        
        liked_rows = db.query("SELECT story_id FROM story_likes WHERE user_id = ?", (user_id,))
        liked_story_ids = [l['story_id'] for l in liked_rows]
    
    # GET ALL AVAILABLE TAGS: For the filter dropdown
    all_tags_rows = db.query("SELECT DISTINCT tag FROM story_tags ORDER BY tag")
    all_tags = [row['tag'] for row in all_tags_rows]
    
    # Fetch tags for each story
    stories_with_tags = []
    for story in stories_data:
        story_dict = dict(story)
        tags_rows = db.query("SELECT tag FROM story_tags WHERE story_id = ?", (story['id'],))
        story_dict['tags'] = [t['tag'] for t in tags_rows]
        stories_with_tags.append(story_dict)
    
    
    # Check if this is an AJAX request for real-time search
    if request.args.get('ajax'):
        return render_template('stories/_stories_grid.html', 
                             stories=stories_with_tags, 
                             page=page, 
                             total_pages=total_pages, 
                             bookmarked_story_ids=bookmarked_story_ids, 
                             liked_story_ids=liked_story_ids)

    return render_template('stories/index.html', 
                           stories=stories_with_tags, 
                           all_tags=all_tags, 
                           selected_tags=tags_filter, 
                           page=page, 
                           total_pages=total_pages, 
                           bookmarked_story_ids=bookmarked_story_ids, 
                           liked_story_ids=liked_story_ids)

# CREATE STORY ROUTE: Handles new story submission, including image uploads and tag associations
@stories_bp.route('/stories/new', methods=['GET', 'POST'])
@login_required
def create_story():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        location = request.form['location']
        
        # Handle file uploads
        images = request.files.getlist('images')
        saved_image_paths = []
        
        allowed_ext = current_app.config.get('ALLOWED_EXTENSIONS', {'png', 'jpg', 'jpeg', 'gif', 'webp'})
        upload_folder = current_app.config.get('UPLOAD_FOLDER')

        for image in images:
            if image and allowed_file(image.filename, allowed_ext):
                filename = secure_filename(image.filename)
                filename = f"{int(time.time())}_{filename}"
                
                # Try GCS Upload first
                gcs_url = upload_to_gcs(image, filename)
                if gcs_url:
                    saved_image_paths.append(gcs_url)
                else:
                    # Fallback to local storage if GCS fails
                    filepath = os.path.join(upload_folder, filename)
                    image.save(filepath)
                    saved_image_paths.append(request.url_root + 'static/uploads/' + filename)
        
        # Validation
        if len(title) < 3 or len(title) > 100:
            flash('Title must be between 3 and 100 characters.', 'danger')
            return render_template('stories/create.html', form=request.form)
            
        if len(content) < 10:
            flash('Content must be at least 10 characters long.', 'danger')
            return render_template('stories/create.html', form=request.form)
        
        # Content Moderation Check
        combined_text = f"{title} {content}"
        if check_content_moderation(combined_text):
            flash('Your content has been flagged by our safety system. Please ensure your post follows community guidelines.', 'danger')
            return render_template('stories/create.html', form=request.form)

        # Fallback to URL if provided
        image_url = request.form.get('image_url')
        if not saved_image_paths and image_url:
            main_image = image_url
        elif saved_image_paths:
            main_image = saved_image_paths[0]
        else:
            main_image = None
            
        author_id = session['user_id']
        db = get_db()
        conn = db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT INTO stories (title, content, author_id, location, image_url) VALUES (?, ?, ?, ?, ?)",
            (title, content, author_id, location, main_image)
        )
        story_id = cursor.lastrowid
        
        # Insert extra images (skip first one if it's already the main image)
        for idx, img_path in enumerate(saved_image_paths[1:]):
            cursor.execute(
                "INSERT INTO story_images (story_id, image_path, position) VALUES (?, ?, ?)",
                (story_id, img_path, idx + 1) # Start position from 1 since 0 is logically the main image
            )
        
        # SAVE TAGS TO DATABASE: Handle tags input (comma-separated, max 5)
        tags_input = request.form.get('tags', '')
        tags = [tag.strip() for tag in tags_input.split(',') if tag.strip()][:5]  # Limit to 5 tags
        for tag in tags:
            cursor.execute("INSERT INTO story_tags (story_id, tag) VALUES (?, ?)", (story_id, tag))
            
        conn.commit()
        flash('Story created successfully!', 'success')
        return redirect(url_for('stories.view_story', story_id=story_id))
        
    return render_template('stories/create.html')

# STORY DETAIL VIEW: Displays a single story with its gallery, tags, and comment thread
@stories_bp.route('/stories/<int:story_id>')
def view_story(story_id):
    db = get_db()
    query = """
        SELECT s.*, u.username as author_name, u.profile_pic
        FROM stories s 
        LEFT JOIN users u ON s.author_id = u.id 
        WHERE s.id = ?
    """
    story = db.query(query, (story_id,), one=True)
    
    if not story:
        return render_template('stories/unavailable.html'), 404
        
    is_bookmarked = False
    is_liked = False
    user_id = session.get('user_id')
    
    if user_id:
        bookmark = db.query("SELECT * FROM bookmarks WHERE user_id = ? AND story_id = ?", (user_id, story_id), one=True)
        is_bookmarked = bool(bookmark)
        
        like_check = db.query("SELECT * FROM story_likes WHERE user_id = ? AND story_id = ?", (user_id, story_id), one=True)
        is_liked = bool(like_check)
        
    additional_images = db.query("SELECT image_path FROM story_images WHERE story_id = ? ORDER BY position ASC", (story_id,))
    story_images = [img['image_path'] for img in additional_images]
    
    # Fetch comments with like counts
    comments_query = """
        SELECT c.id, c.story_id, c.user_id, c.content, c.likes,
                c.created_at,
               u.username, u.role, u.profile_pic 
        FROM comments c 
        JOIN users u ON c.user_id = u.id 
        WHERE c.story_id = ? 
        ORDER BY c.created_at DESC
    """
    comments_raw = db.query(comments_query, (story_id,))
    
    # Convert to list of dicts and add is_liked and replies for each comment
    comments = []
    for comment in comments_raw:
        comment_dict = dict(comment)
        
        # Check if current user liked this comment
        if user_id:
            comment_like = db.query("SELECT * FROM comment_likes WHERE user_id = ? AND comment_id = ?", 
                                   (user_id, comment['id']), one=True)
            comment_dict['is_liked'] = bool(comment_like)
        else:
            comment_dict['is_liked'] = False
        
        # Fetch replies for this comment
        replies_query = """
            SELECT cr.id, cr.user_id, cr.content, u.username,
                   cr.created_at
            FROM comment_replies cr
            JOIN users u ON cr.user_id = u.id
            WHERE cr.comment_id = ?
            ORDER BY cr.created_at ASC
        """
        comment_dict['replies'] = db.query(replies_query, (comment['id'],))
        comments.append(comment_dict)
    
    # FETCH TAGS FROM DATABASE: Get all tags associated with this story
    tags_rows = db.query("SELECT tag FROM story_tags WHERE story_id = ?", (story_id,))
    story_tags = [row['tag'] for row in tags_rows]
        
    # Get AI Insight for location
    ai_insight = None
    if story['location']:
        ai_insight = get_location_insight(story['location'])

    return render_template('stories/view.html', story=story, is_bookmarked=is_bookmarked, is_liked=is_liked, comments=comments, story_images=story_images, story_tags=story_tags, ai_insight=ai_insight)

# MY FAVOURITES VIEW: Displays stories bookmarked by the logged-in user with filter support
@stories_bp.route('/stories/bookmarks')
@login_required
def my_bookmarks():
    db = get_db()
    user_id = session['user_id']
    search_query = request.args.get('search', '').strip()
    location_filter = request.args.get('location', '').strip()
    sort_option = request.args.get('sort', 'newest')
    tags_filter = request.args.getlist('tags')  # Multiple tags can be selected
    
    query = """
        SELECT DISTINCT s.*, u.username, u.profile_pic FROM stories s
        JOIN bookmarks b ON s.id = b.story_id
        LEFT JOIN users u ON s.author_id = u.id
    """
    params = []
    
    # FILTER BY TAGS: Join with story_tags if tags filter is applied
    if tags_filter:
        placeholders = ','.join(['?' for _ in tags_filter])
        query += f" INNER JOIN story_tags st ON s.id = st.story_id AND st.tag IN ({placeholders})"
        params.extend(tags_filter)
    
    query += " WHERE b.user_id = ?"
    params.append(user_id)
    
    if search_query:
        query += " AND (s.title LIKE ? OR s.content LIKE ?)"
        params.extend([f"%{search_query}%", f"%{search_query}%"])
        
        
    if location_filter:
        query += " AND s.location LIKE ?"
        params.append(f"%{location_filter}%")
        
    if sort_option == 'likes':
        query += " ORDER BY s.likes DESC"
    else:
        query += " ORDER BY b.id DESC"
        
    stories_data = db.query(query, tuple(params))
    
    # Get user's liked stories for the heart icon status
    liked_rows = db.query("SELECT story_id FROM story_likes WHERE user_id = ?", (user_id,))
    liked_story_ids = [l['story_id'] for l in liked_rows]
    
    # Fetch tags for each story
    stories_with_tags = []
    for story in stories_data:
        story_dict = dict(story)
        tags_rows = db.query("SELECT tag FROM story_tags WHERE story_id = ?", (story['id'],))
        story_dict['tags'] = [t['tag'] for t in tags_rows]
        stories_with_tags.append(story_dict)
        
    # Get all tags for filter
    all_tags_rows = db.query("SELECT DISTINCT tag FROM story_tags ORDER BY tag")
    all_tags = [row['tag'] for row in all_tags_rows]

    if request.args.get('ajax'):
        return render_template('stories/_favourites_grid.html', 
                             stories=stories_with_tags, 
                             liked_story_ids=liked_story_ids)
    
    return render_template('stories/favourites.html', 
                           stories=stories_with_tags, 
                           liked_story_ids=liked_story_ids,
                           all_tags=all_tags,
                           selected_tags=tags_filter)
    bookmarked_story_ids = [b['id'] for b in bookmarks]

    likes_query = "SELECT story_id FROM story_likes WHERE user_id = ?"
    liked_rows = db.query(likes_query, (user_id,))
    liked_story_ids = [l['story_id'] for l in liked_rows]
    
    # GET ALL AVAILABLE TAGS: For the filter dropdown
    all_tags_rows = db.query("SELECT DISTINCT tag FROM story_tags ORDER BY tag")
    all_tags = [row['tag'] for row in all_tags_rows]
    
    # Fetch tags for each story
    stories_with_tags = []
    for story in bookmarks:
        story_dict = dict(story)
        tags_rows = db.query("SELECT tag FROM story_tags WHERE story_id = ?", (story['id'],))
        story_dict['tags'] = [t['tag'] for t in tags_rows]
        stories_with_tags.append(story_dict)
    
    return render_template('stories/favourites.html', stories=stories_with_tags, bookmarked_story_ids=bookmarked_story_ids, liked_story_ids=liked_story_ids, all_tags=all_tags, selected_tags=tags_filter)

# TOGGLE BOOKMARK ACTION: Saves or removes a story from the user's favourites list
@stories_bp.route('/stories/<int:story_id>/bookmark', methods=['POST'])
@login_required
def toggle_bookmark(story_id):
    db = get_db()
    conn = db.get_connection()
    user_id = session['user_id']
    
    exists = db.query("SELECT * FROM bookmarks WHERE user_id = ? AND story_id = ?", (user_id, story_id), one=True)
    if exists:
        conn.execute("DELETE FROM bookmarks WHERE user_id = ? AND story_id = ?", (user_id, story_id))
        is_bookmarked = False
    else:
        conn.execute("INSERT INTO bookmarks (user_id, story_id) VALUES (?, ?)", (user_id, story_id))
        is_bookmarked = True
        
    conn.commit()
    
    # Return JSON for AJAX requests
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        from flask import jsonify
        return jsonify({'success': True, 'is_bookmarked': is_bookmarked})
    
    return redirect(request.referrer or url_for('stories.view_story', story_id=story_id))

# TOGGLE LIKE ACTION: Increments or decrements story like count and tracks user interaction
@stories_bp.route('/stories/<int:story_id>/like', methods=['POST'])
@login_required
def toggle_like(story_id):
    db = get_db()
    conn = db.get_connection()
    user_id = session['user_id']
    
    exists = db.query("SELECT * FROM story_likes WHERE user_id = ? AND story_id = ?", (user_id, story_id), one=True)
    
    if exists:
        conn.execute("DELETE FROM story_likes WHERE user_id = ? AND story_id = ?", (user_id, story_id))
        conn.execute("UPDATE stories SET likes = likes - 1 WHERE id = ?", (story_id,))
        is_liked = False
    else:
        conn.execute("INSERT INTO story_likes (user_id, story_id) VALUES (?, ?)", (user_id, story_id))
        conn.execute("UPDATE stories SET likes = likes + 1 WHERE id = ?", (story_id,))
        is_liked = True
        
    conn.commit()
    
    # Notify Story Author if liked (and not by themselves)
    if is_liked:
        story_info = db.query("SELECT author_id, title FROM stories WHERE id = ?", (story_id,), one=True)
        if story_info and story_info['author_id'] != user_id:
            sender = db.query("SELECT username FROM users WHERE id = ?", (user_id,), one=True)
            create_notification(
                story_info['author_id'],
                'Like',
                f"{sender['username']} liked your story: {story_info['title']}",
                url_for('stories.view_story', story_id=story_id)
            )
    
    # Get updated like count
    story = db.query("SELECT likes FROM stories WHERE id = ?", (story_id,), one=True)
    likes_count = story['likes'] if story else 0
    
    # Return JSON for AJAX requests
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        from flask import jsonify
        return jsonify({'success': True, 'is_liked': is_liked, 'likes': likes_count})
    
    return redirect(request.referrer or url_for('stories.stories_list'))

# EDIT STORY ROUTE: Allows authors to modify story text, images, and tags
@stories_bp.route('/stories/<int:story_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_story(story_id):
    db = get_db()
    story = db.query("SELECT * FROM stories WHERE id = ?", (story_id,), one=True)
    
    if not story:
        flash('Story not found.', 'danger')
        return redirect(url_for('stories.stories_list'))
        
    if story['author_id'] != session['user_id']:
        flash('You are not authorized to edit this story.', 'danger')
        return redirect(url_for('stories.stories_list'))
        
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        location = request.form['location']
        
        if len(title) < 3 or len(title) > 100:
            flash('Title must be between 3 and 100 characters.', 'danger')
            return redirect(url_for('stories.edit_story', story_id=story_id))
            
        if len(content) < 10:
             flash('Content must be at least 10 characters long.', 'danger')
             return redirect(url_for('stories.edit_story', story_id=story_id))
        
        # Content Moderation Check
        combined_text = f"{title} {content}"
        if check_content_moderation(combined_text):
            flash('Your content has been flagged by our safety system. Please ensure your post follows community guidelines.', 'danger')
            return redirect(url_for('stories.edit_story', story_id=story_id))

        conn = db.get_connection()
        conn.execute("UPDATE stories SET title = ?, content = ?, location = ? WHERE id = ?", 
                     (title, content, location, story_id))
        
        if request.form.get('delete_main_image'):
            conn.execute("UPDATE stories SET image_url = NULL WHERE id = ?", (story_id,))

        images_to_delete = request.form.getlist('delete_image_ids')
        if images_to_delete:
            for img_id in images_to_delete:
                conn.execute("DELETE FROM story_images WHERE id = ? AND story_id = ?", (img_id, story_id))

        images = request.files.getlist('images')
        saved_image_paths = []
        allowed_ext = current_app.config.get('ALLOWED_EXTENSIONS')
        upload_folder = current_app.config.get('UPLOAD_FOLDER')

        if images:
             for image in images:
                if image and allowed_file(image.filename, allowed_ext):
                    filename = secure_filename(image.filename)
                    filename = f"{int(time.time())}_{filename}"
                    
                    # Try GCS Upload first
                    gcs_url = upload_to_gcs(image, filename)
                    if gcs_url:
                        saved_image_paths.append(gcs_url)
                    else:
                        # Fallback to local storage
                        filepath = os.path.join(upload_folder, filename)
                        image.save(filepath)
                        saved_image_paths.append(request.url_root + 'static/uploads/' + filename)
        
        for img_path in saved_image_paths:
            current_story = db.query("SELECT image_url FROM stories WHERE id=?", (story_id,), one=True)
            if not current_story['image_url']:
                 conn.execute("UPDATE stories SET image_url = ? WHERE id = ?", (img_path, story_id))
            else:
                 conn.execute("INSERT INTO story_images (story_id, image_path) VALUES (?, ?)", (story_id, img_path))
        
        # Handle media rearrangement if order is provided
        media_order = request.form.get('media_order')
        if media_order:
            order_list = [item for item in media_order.split(',') if item]
            
            # Map new-X tokens to actual IDs of new images we just inserted
            # saved_image_paths contains path strings. We just inserted them above.
            # But wait, the insertion above doesn't return IDs. 
            # Let's rewrite the insertion to be more precise for the order list.
            
            # 1. Clear current positions (optional but keeps things clean)
            conn.execute("UPDATE story_images SET position = NULL WHERE story_id = ?", (story_id,))
            
            # 2. Re-resolve order_list to replace 'new-X' with actual IDs
            # Total images = existing + new
            # Let's find newly inserted IDs
            new_ids = []
            # Note: saved_image_paths contains path of ALL uploaded images (including the one that might have become main)
            # This is a bit tricky because some might have become the "main" if current_story['image_url'] was empty.
            # Let's assume the user is using the unified UI.
            
            # Get latest story_images (including those just inserted)
            # This is slightly inefficient but safe.
            all_current_images = db.query("SELECT id, image_path FROM story_images WHERE story_id = ?", (story_id,))
            path_to_id = {img['image_path']: img['id'] for img in all_current_images}
            
            # Resolve the order list
            resolved_order = []
            for item in order_list:
                if item == 'main':
                    resolved_order.append('main')
                elif item.startswith('new-'):
                    # We need to find which saved path corresponds to this 'new-X'
                    # The frontend sends them in index order
                    try:
                        idx = int(item.split('-')[1])
                        if idx < len(saved_image_paths):
                            path = saved_image_paths[idx]
                            img_id = path_to_id.get(path)
                            if img_id:
                                resolved_order.append(img_id)
                    except (ValueError, IndexError):
                        pass
                else:
                    try:
                        resolved_order.append(int(item))
                    except ValueError:
                        pass

            # 3. Handle Main Image Swap IF the first item is not 'main'
            if resolved_order and resolved_order[0] != 'main':
                target = resolved_order[0] # This is an ID now
                # Get existing main
                curr_story = db.query("SELECT image_url FROM stories WHERE id = ?", (story_id,), one=True)
                old_main_path = curr_story['image_url']
                
                # Get new main path
                new_main_img = db.query("SELECT image_path FROM story_images WHERE id = ?", (target,), one=True)
                if new_main_img:
                    new_main_path = new_main_img['image_path']
                    
                    # Swap
                    conn.execute("UPDATE stories SET image_url = ? WHERE id = ?", (new_main_path, story_id))
                    conn.execute("UPDATE story_images SET image_path = ? WHERE id = ?", (old_main_path, target))
                    # Note: ID 'target' now logically points to 'old_main_path'
                    # and story.image_url is 'new_main_path' (which was 'target''s content)
            
            # 4. Update all positions in story_images based on final resolved_order
            for idx, item in enumerate(resolved_order):
                if item != 'main':
                    conn.execute("UPDATE story_images SET position = ? WHERE id = ? AND story_id = ?", 
                                 (idx, item, story_id))

        conn.commit()
        flash('Story updated successfully!', 'success')
        return redirect(url_for('stories.view_story', story_id=story_id))
    
    story_images = db.query("SELECT * FROM story_images WHERE story_id = ?", (story_id,))
    
    # Fetch existing tags for the form
    existing_tags = db.query("SELECT tag FROM story_tags WHERE story_id = ?", (story_id,))
    story_tags = ','.join([t['tag'] for t in existing_tags])
    
    return render_template('stories/edit.html', story=story, story_images=story_images, story_tags=story_tags)

# DELETE STORY IMAGE: AJAX endpoint for instant image deletion
@stories_bp.route('/stories/<int:story_id>/delete-image/<int:image_id>', methods=['POST'])
@login_required
def delete_story_image(story_id, image_id):
    db = get_db()
    story = db.query("SELECT * FROM stories WHERE id = ?", (story_id,), one=True)
    
    if not story or story['author_id'] != session['user_id']:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            from flask import jsonify
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        flash('You are not authorized to delete this image.', 'danger')
        return redirect(url_for('stories.stories_list'))
    
    conn = db.get_connection()
    conn.execute("DELETE FROM story_images WHERE id = ? AND story_id = ?", (image_id, story_id))
    conn.commit()
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        from flask import jsonify
        return jsonify({'success': True})
    
    flash('Image deleted.', 'success')
    return redirect(url_for('stories.edit_story', story_id=story_id))

# DELETE MAIN IMAGE: AJAX endpoint for deleting the main story image
@stories_bp.route('/stories/<int:story_id>/delete-main-image', methods=['POST'])
@login_required
def delete_main_image(story_id):
    db = get_db()
    story = db.query("SELECT * FROM stories WHERE id = ?", (story_id,), one=True)
    
    if not story or story['author_id'] != session['user_id']:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            from flask import jsonify
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        flash('You are not authorized to delete this image.', 'danger')
        return redirect(url_for('stories.stories_list'))
    
    conn = db.get_connection()
    conn.execute("UPDATE stories SET image_url = NULL WHERE id = ?", (story_id,))
    conn.commit()
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        from flask import jsonify
        return jsonify({'success': True})
    
    flash('Main image deleted.', 'success')
    return redirect(url_for('stories.edit_story', story_id=story_id))

# REPORT COMMENT ACTION: Allows users to report a comment
@stories_bp.route('/comment/<int:comment_id>/report', methods=['POST'])
@login_required
def report_comment(comment_id):
    reason = request.form.get('reason')
    if not reason:
        flash('Please provide a reason for reporting.', 'warning')
        return redirect(request.referrer)
        
    db = get_db()
    conn = db.get_connection()
    user_id = session['user_id']
    
    # Check if already reported
    existing = db.query("SELECT id FROM reports WHERE reporter_id = ? AND target_type = 'comment' AND target_id = ?", 
                       (user_id, comment_id), one=True)
    
    if existing:
        flash('You have already reported this comment.', 'info')
    else:
        conn.execute("INSERT INTO reports (reporter_id, target_type, target_id, reason) VALUES (?, 'comment', ?, ?)",
                    (user_id, comment_id, reason))
        conn.commit()
        flash('Comment reported. Thank you for helping keep our community safe.', 'success')
        
    return redirect(request.referrer)

# REPORT STORY ACTION: Allows users to flag inappropriate content
@stories_bp.route('/stories/<int:story_id>/report', methods=['POST'])
@login_required
def report_story(story_id):
    reason = request.form.get('reason')
    if not reason:
        flash('Please provide a reason for reporting.', 'warning')
        return redirect(url_for('stories.view_story', story_id=story_id))
        
    db = get_db()
    conn = db.get_connection()
    user_id = session['user_id']
    
    # Check if already reported
    existing = db.query("SELECT id FROM reports WHERE reporter_id = ? AND target_type = 'story' AND target_id = ?", 
                       (user_id, story_id), one=True)
    
    if existing:
        flash('You have already reported this story.', 'info')
    else:
        conn.execute("INSERT INTO reports (reporter_id, target_type, target_id, reason) VALUES (?, 'story', ?, ?)",
                    (user_id, story_id, reason))
        conn.commit()
        flash('Story reported. Thank you for helping keep our community safe.', 'success')
        
    return redirect(url_for('stories.view_story', story_id=story_id))

# DELETE STORY ACTION: Permanently removes a story and its related data (likes, bookmarks, images)
@stories_bp.route('/stories/<int:story_id>/delete', methods=['POST'])
@login_required
def delete_story(story_id):
    db = get_db()
    story = db.query("SELECT * FROM stories WHERE id = ?", (story_id,), one=True)
    
    if not story:
        return "Story not found", 404
        
    if story['author_id'] != session['user_id']:
        flash('You can only delete your own stories.', 'danger')
        return redirect(url_for('stories.view_story', story_id=story_id))
        
    conn = db.get_connection()
    conn.execute("DELETE FROM bookmarks WHERE story_id = ?", (story_id,))
    conn.execute("DELETE FROM story_likes WHERE story_id = ?", (story_id,))
    conn.execute("DELETE FROM comments WHERE story_id = ?", (story_id,))
    conn.execute("DELETE FROM stories WHERE id = ?", (story_id,))
    conn.commit()
    flash('Story deleted successfully.', 'success')
    return redirect(url_for('stories.stories_list'))

# ADD COMMENT ACTION: Appends a new user comment to a story thread
@stories_bp.route('/stories/<int:story_id>/comment', methods=['POST'])
@login_required
def add_comment(story_id):
    content = request.form.get('content', '')
    if not content.strip():
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': 'Comment cannot be empty'}), 400
        return redirect(url_for('stories.view_story', story_id=story_id))
    
    # Content Moderation Check
    if check_content_moderation(content):
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': 'Your comment has been flagged by our safety system.'}), 400
        flash('Your comment has been flagged by our safety system. Please ensure it follows community guidelines.', 'danger')
        return redirect(url_for('stories.view_story', story_id=story_id))
        
    user_id = session['user_id']
    db = get_db()
    conn = db.get_connection()
    cursor = conn.execute("INSERT INTO comments (story_id, user_id, content) VALUES (?, ?, ?)", (story_id, user_id, content))
    comment_id = cursor.lastrowid
    conn.commit()
    
    # Notify Story Author (if not by themselves)
    story_info = db.query("SELECT author_id, title FROM stories WHERE id = ?", (story_id,), one=True)
    if story_info and story_info['author_id'] != user_id:
        sender = db.query("SELECT username FROM users WHERE id = ?", (user_id,), one=True)
        create_notification(
            story_info['author_id'],
            'Comment',
            f"{sender['username']} commented on your story: {story_info['title']}",
            url_for('stories.view_story', story_id=story_id)
        )
    
    # Check if AJAX request
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        # Fetch user info for the response
        user = db.query("SELECT username, profile_pic FROM users WHERE id = ?", (user_id,), one=True)
        return jsonify({
            'success': True,
            'comment': {
                'id': comment_id,
                'content': content,
                'username': user['username'],
                'profile_pic': user['profile_pic'] or f"https://ui-avatars.com/api/?name={user['username']}",
                'created_at': 'Just now',
                'likes': 0,
                'is_liked': False,
                'user_id': user_id
            }
        })
    
    flash('Comment posted successfully!', 'success')
    return redirect(url_for('stories.view_story', story_id=story_id))

# Comment Management inside stories blueprint
# EDIT COMMENT ACTION: Updates the content of an existing user comment
@stories_bp.route('/comment/<int:comment_id>/edit', methods=['POST'])
@login_required
def edit_comment(comment_id):
    new_content = request.form['content']
    
    # Content Moderation Check
    if check_content_moderation(new_content):
        flash('Your updated comment has been flagged by our safety system. Please ensure it follows community guidelines.', 'danger')
        return redirect(request.referrer)
        
    user_id = session['user_id']
    
    db = get_db()
    comment = db.query("SELECT * FROM comments WHERE id = ?", (comment_id,), one=True)
    
    if not comment:
        flash('Comment not found.', 'danger')
        return redirect(request.referrer)
        
    if comment['user_id'] != user_id:
        flash('You can only edit your own comments.', 'danger')
        return redirect(request.referrer)
        
    conn = db.get_connection()
    conn.execute("UPDATE comments SET content = ? WHERE id = ?", (new_content, comment_id))
    conn.commit()
    flash('Comment updated.', 'success')
    return redirect(request.referrer)

# DELETE COMMENT ACTION: Removes a user comment from a story thread
@stories_bp.route('/comment/<int:comment_id>/delete', methods=['POST'])
@login_required
def delete_comment(comment_id):
    user_id = session['user_id']
    
    db = get_db()
    comment = db.query("SELECT * FROM comments WHERE id = ?", (comment_id,), one=True)
    
    if not comment:
        return redirect(request.referrer)
        
    if comment['user_id'] != user_id:
        flash('Unauthorized action.', 'danger')
        return redirect(request.referrer)
        
    conn = db.get_connection()
    # Delete any replies to this comment
    conn.execute("DELETE FROM comment_replies WHERE comment_id = ?", (comment_id,))
    # Delete any likes on this comment
    conn.execute("DELETE FROM comment_likes WHERE comment_id = ?", (comment_id,))
    conn.execute("DELETE FROM comments WHERE id = ?", (comment_id,))
    conn.commit()
    flash('Comment deleted.', 'info')
    return redirect(request.referrer)

# TOGGLE COMMENT LIKE ACTION: Like or unlike a comment
@stories_bp.route('/comment/<int:comment_id>/like', methods=['POST'])
@login_required
def toggle_comment_like(comment_id):
    user_id = session['user_id']
    db = get_db()
    conn = db.get_connection()
    
    # Check if already liked
    existing = db.query("SELECT * FROM comment_likes WHERE user_id = ? AND comment_id = ?", 
                       (user_id, comment_id), one=True)
    
    if existing:
        conn.execute("DELETE FROM comment_likes WHERE user_id = ? AND comment_id = ?", 
                    (user_id, comment_id))
        conn.execute("UPDATE comments SET likes = likes - 1 WHERE id = ?", (comment_id,))
        is_liked = False
    else:
        conn.execute("INSERT INTO comment_likes (user_id, comment_id) VALUES (?, ?)", 
                    (user_id, comment_id))
        conn.execute("UPDATE comments SET likes = likes + 1 WHERE id = ?", (comment_id,))
        is_liked = True
    
    conn.commit()
    
    # Notify Comment Author if liked (and not by themselves)
    if is_liked:
        comment_info = db.query("SELECT user_id, story_id FROM comments WHERE id = ?", (comment_id,), one=True)
        if comment_info and comment_info['user_id'] != user_id:
            sender = db.query("SELECT username FROM users WHERE id = ?", (user_id,), one=True)
            # Find story title for better context
            story = db.query("SELECT title FROM stories WHERE id = ?", (comment_info['story_id'],), one=True)
            story_title = story['title'] if story else "your story"
            create_notification(
                comment_info['user_id'],
                'Like',
                f"{sender['username']} liked your comment on {story_title}",
                url_for('stories.view_story', story_id=comment_info['story_id'])
            )
    
    # Get updated like count
    comment = db.query("SELECT likes FROM comments WHERE id = ?", (comment_id,), one=True)
    new_likes = comment['likes'] if comment else 0
    
    # Check if AJAX request
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'success': True, 'is_liked': is_liked, 'likes': new_likes})
    
    return redirect(request.referrer)

# ADD COMMENT REPLY ACTION: Adds a reply to a comment
@stories_bp.route('/comment/<int:comment_id>/reply', methods=['POST'])
@login_required
def add_comment_reply(comment_id):
    user_id = session['user_id']
    content = request.form.get('content', '').strip()
    
    if not content:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': 'Reply cannot be empty'}), 400
        flash('Reply cannot be empty.', 'warning')
        return redirect(request.referrer)
    
    db = get_db()
    conn = db.get_connection()
    cursor = conn.execute("INSERT INTO comment_replies (comment_id, user_id, content) VALUES (?, ?, ?)",
                (comment_id, user_id, content))
    reply_id = cursor.lastrowid
    conn.commit()
    
    # Notify Parent Comment Author (if not by themselves)
    comment_info = db.query("SELECT user_id, story_id FROM comments WHERE id = ?", (comment_id,), one=True)
    if comment_info and comment_info['user_id'] != user_id:
        sender = db.query("SELECT username FROM users WHERE id = ?", (user_id,), one=True)
        create_notification(
            comment_info['user_id'],
            'Reply',
            f"{sender['username']} replied to your comment",
            url_for('stories.view_story', story_id=comment_info['story_id'])
        )
    
    # Check if AJAX request
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        user = db.query("SELECT username FROM users WHERE id = ?", (user_id,), one=True)
        return jsonify({
            'success': True,
            'reply': {
                'id': reply_id,
                'content': content,
                'username': user['username'],
                'created_at': 'Just now',
                'user_id': user_id
            }
        })
    
    flash('Reply added.', 'success')
    return redirect(request.referrer)

# EDIT COMMENT REPLY ACTION: Updates the content of an existing reply
@stories_bp.route('/comment/reply/<int:reply_id>/edit', methods=['POST'])
@login_required
def edit_comment_reply(reply_id):
    content = request.form.get('content', '').strip()
    user_id = session['user_id']
    
    if not content:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': 'Reply cannot be empty'}), 400
        flash('Reply cannot be empty.', 'warning')
        return redirect(request.referrer)
    
    db = get_db()
    
    # Verify ownership
    reply = db.query("SELECT * FROM comment_replies WHERE id = ?", (reply_id,), one=True)
    if not reply:
        return jsonify({'success': False, 'error': 'Reply not found'}), 404
        
    if reply['user_id'] != user_id:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        flash('Unauthorized action.', 'danger')
        return redirect(request.referrer)
    
    conn = db.get_connection()
    conn.execute("UPDATE comment_replies SET content = ? WHERE id = ?", (content, reply_id))
    conn.commit()
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'success': True, 'content': content})
    
    flash('Reply updated.', 'success')
    return redirect(request.referrer)

# DELETE COMMENT REPLY ACTION: Removes a reply from a comment
@stories_bp.route('/comment/reply/<int:reply_id>/delete', methods=['POST'])
@login_required
def delete_comment_reply(reply_id):
    user_id = session['user_id']
    db = get_db()
    
    reply = db.query("SELECT * FROM comment_replies WHERE id = ?", (reply_id,), one=True)
    
    if not reply:
        return redirect(request.referrer)
    
    if reply['user_id'] != user_id:
        flash('Unauthorized action.', 'danger')
        return redirect(request.referrer)
    
    conn = db.get_connection()
    conn.execute("DELETE FROM comment_replies WHERE id = ?", (reply_id,))
    conn.commit()
    
    flash('Reply deleted.', 'info')
    return redirect(request.referrer)
