from flask import Blueprint, render_template, request, redirect, url_for, session, flash, current_app
from werkzeug.utils import secure_filename
from utils import get_db, login_required, allowed_file
import os
import time
import math

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
    
    return render_template('stories/index.html', stories=stories_with_tags, page=page, total_pages=total_pages, bookmarked_story_ids=bookmarked_story_ids, liked_story_ids=liked_story_ids, all_tags=all_tags, selected_tags=tags_filter)

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
                filepath = os.path.join(upload_folder, filename)
                image.save(filepath)
                saved_image_paths.append(f"uploads/{filename}")
        
        # Validation
        if len(title) < 3 or len(title) > 100:
            flash('Title must be between 3 and 100 characters.', 'danger')
            return render_template('stories/create.html', form=request.form)
            
        if len(content) < 10:
            flash('Content must be at least 10 characters long.', 'danger')
            return render_template('stories/create.html', form=request.form)

        # Fallback to URL if provided
        image_url = request.form.get('image_url')
        if not saved_image_paths and image_url:
            main_image = image_url
        elif saved_image_paths:
            main_image = request.url_root + 'static/' + saved_image_paths[0]
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
        
        # Insert extra images
        for img_path in saved_image_paths:
            full_url = request.url_root + 'static/' + img_path
            cursor.execute(
                "INSERT INTO story_images (story_id, image_path) VALUES (?, ?)",
                (story_id, full_url)
            )
        
        # SAVE TAGS TO DATABASE: Handle tags input (comma-separated, max 5)
        tags_input = request.form.get('tags', '')
        tags = [tag.strip() for tag in tags_input.split(',') if tag.strip()][:5]  # Limit to 5 tags
        for tag in tags:
            cursor.execute("INSERT INTO story_tags (story_id, tag) VALUES (?, ?)", (story_id, tag))
            
        conn.commit()
        flash('Story created successfully!', 'success')
        return redirect(url_for('stories.stories_list'))
        
    return render_template('stories/create.html')

# STORY DETAIL VIEW: Displays a single story with its gallery, tags, and comment thread
@stories_bp.route('/stories/<int:story_id>')
def view_story(story_id):
    db = get_db()
    query = """
        SELECT s.*, u.username as author_name 
        FROM stories s 
        LEFT JOIN users u ON s.author_id = u.id 
        WHERE s.id = ?
    """
    story = db.query(query, (story_id,), one=True)
    
    if not story:
        return "Story not found", 404
        
    is_bookmarked = False
    is_liked = False
    
    if 'user_id' in session:
        user_id = session['user_id']
        bookmark = db.query("SELECT * FROM bookmarks WHERE user_id = ? AND story_id = ?", (user_id, story_id), one=True)
        is_bookmarked = bool(bookmark)
        
        like_check = db.query("SELECT * FROM story_likes WHERE user_id = ? AND story_id = ?", (user_id, story_id), one=True)
        is_liked = bool(like_check)
        
    additional_images = db.query("SELECT image_path FROM story_images WHERE story_id = ?", (story_id,))
    story_images = [img['image_path'] for img in additional_images]
    
    comments_query = """
        SELECT c.id, c.story_id, c.user_id, c.content, 
               datetime(c.created_at, '+8 hours') as created_at,
               u.username, u.role, u.profile_pic 
        FROM comments c 
        JOIN users u ON c.user_id = u.id 
        WHERE c.story_id = ? 
        ORDER BY c.created_at DESC
    """
    comments = db.query(comments_query, (story_id,))
    
    # FETCH TAGS FROM DATABASE: Get all tags associated with this story
    tags_rows = db.query("SELECT tag FROM story_tags WHERE story_id = ?", (story_id,))
    story_tags = [row['tag'] for row in tags_rows]
        
    return render_template('stories/view.html', story=story, is_bookmarked=is_bookmarked, is_liked=is_liked, comments=comments, story_images=story_images, story_tags=story_tags)

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
    
    bookmarks = db.query(query, tuple(params))
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
    else:
        conn.execute("INSERT INTO bookmarks (user_id, story_id) VALUES (?, ?)", (user_id, story_id))
        
    conn.commit()
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
    else:
        conn.execute("INSERT INTO story_likes (user_id, story_id) VALUES (?, ?)", (user_id, story_id))
        conn.execute("UPDATE stories SET likes = likes + 1 WHERE id = ?", (story_id,))
        
    conn.commit()
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
                    filepath = os.path.join(upload_folder, filename)
                    image.save(filepath)
                    saved_image_paths.append(f"uploads/{filename}")
        
        for img_path in saved_image_paths:
            current_story = db.query("SELECT image_url FROM stories WHERE id=?", (story_id,), one=True)
            if not current_story['image_url']:
                 conn.execute("UPDATE stories SET image_url = ? WHERE id = ?", (request.url_root + 'static/' + img_path, story_id))
            else:
                 conn.execute("INSERT INTO story_images (story_id, image_path) VALUES (?, ?)", (story_id, img_path))
        
        # UPDATE TAGS IN DATABASE: Delete old tags and insert new ones
        conn.execute("DELETE FROM story_tags WHERE story_id = ?", (story_id,))
        tags_input = request.form.get('tags', '')
        tags = [tag.strip() for tag in tags_input.split(',') if tag.strip()][:5]
        for tag in tags:
            conn.execute("INSERT INTO story_tags (story_id, tag) VALUES (?, ?)", (story_id, tag))
            
        conn.commit()
        flash('Story updated successfully!', 'success')
        return redirect(url_for('stories.view_story', story_id=story_id))
    
    story_images = db.query("SELECT * FROM story_images WHERE story_id = ?", (story_id,))
    
    # Fetch existing tags for the form
    existing_tags = db.query("SELECT tag FROM story_tags WHERE story_id = ?", (story_id,))
    story_tags = ','.join([t['tag'] for t in existing_tags])
    
    return render_template('stories/edit.html', story=story, story_images=story_images, story_tags=story_tags)

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
    content = request.form['content']
    if not content.strip():
        return redirect(url_for('stories.view_story', story_id=story_id))
        
    user_id = session['user_id']
    db = get_db()
    conn = db.get_connection()
    conn.execute("INSERT INTO comments (story_id, user_id, content) VALUES (?, ?, ?)", (story_id, user_id, content))
    conn.commit()
    return redirect(url_for('stories.view_story', story_id=story_id))

# Comment Management inside stories blueprint
# EDIT COMMENT ACTION: Updates the content of an existing user comment
@stories_bp.route('/comment/<int:comment_id>/edit', methods=['POST'])
@login_required
def edit_comment(comment_id):
    new_content = request.form['content']
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
    conn.execute("DELETE FROM comments WHERE id = ?", (comment_id,))
    conn.commit()
    flash('Comment deleted.', 'info')
    return redirect(request.referrer)
