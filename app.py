# app.py
import os
import sqlite3
from config import DevelopmentConfig, ProductionConfig
from flask import Flask, render_template, request, redirect, url_for, flash, session, g, jsonify
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from database import (
    init_db, close_db, create_user, get_user_by_email, get_user_by_id,
    create_resource, get_recent_resources, get_resource_by_id, send_message, update_resource,
    delete_resource, get_all_resources, get_top_reviews, get_conversation, get_inbox, 
    create_space, get_all_spaces, get_space_by_id, create_event, get_all_events, get_event_by_id,
    get_db, get_resources_by_user, get_events_by_user, get_spaces_by_user, book_resource, book_event,
    book_space, get_event_bookings_by_user, get_resource_bookings_by_user, get_space_bookings_by_user

)

app = Flask(__name__)

# Configuration for file uploads
UPLOAD_FOLDER = 'static/uploads/profile_images'
UPLOAD_FOLDER = 'static/uploads/resources'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Create upload folder if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    """Check if the uploaded file is of an allowed type."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

if os.getenv("FLASK_ENV") == "production":
    app.config.from_object(ProductionConfig)
else:
    app.config.from_object(DevelopmentConfig)

@app.before_request
def initialize_database():
    init_db()

@app.teardown_appcontext
def shutdown_session(exception=None):
    close_db()

@app.route('/')
@app.route('/index')
def index():
    recent_resources = get_recent_resources()
    top_reviews = get_top_reviews()
    return render_template('index.html', recent_resources=recent_resources, top_reviews=top_reviews)

@app.route('/registration')
def registration():
    return render_template('register.html')

@app.route('/register', methods=['POST'])
def register():
    name = request.form['name']
    email = request.form['email']
    password = request.form['password']
    location = request.form.get('location', '')
    profile_image = request.files.get('profile_image')

    if not name or not email or not password:
        flash('Name, email, and password are required', 'error')
        return redirect(url_for('registration'))

    # Handle profile image upload
    profile_image_path = None
    if profile_image and allowed_file(profile_image.filename):
        filename = secure_filename(profile_image.filename)
        profile_image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        profile_image.save(profile_image_path)
    elif profile_image:
        flash('Invalid file type. Only PNG, JPG, and JPEG files are allowed.', 'error')
        return redirect(url_for('registration'))

    # Store user in the database
    user = create_user(name, email, password, location, profile_image_path)
    if user is None:
        flash('Email already registered', 'error')
        return redirect(url_for('registration'))

    flash('Registration successful', 'success')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if not email or not password:
            flash('Email and password are required', 'error')
            return redirect(url_for('login'))

        user = get_user_by_email(email)
        if user is None or not check_password_hash(user['password'], password):
            flash('Invalid email or password', 'error')
            return redirect(url_for('login'))

        session['user_id'] = user['id']
        flash('Login successful', 'success')
        return redirect(url_for('profile'))

    return render_template('login.html')

@app.route('/profile')
def profile():
    # Ensure user is logged in
    user_id = session.get('user_id')
    if user_id is None:
        flash('Please log in to access your profile', 'error')
        return redirect(url_for('login'))

    # Fetch user information
    user = get_user_by_id(user_id)
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('login'))

    # Fetch user-specific data
    resources = get_resources_by_user(user_id)
    events = get_events_by_user(user_id)
    spaces = get_spaces_by_user(user_id)

    # Render the profile template with user-specific data
    return render_template(
        'profile.html',
        user=user,
        resources=resources,
        events=events,
        spaces=spaces
    )


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

# Resource Routes
@app.route('/resource/new', methods=['GET', 'POST'])
def new_resource():
    user_id = session.get('user_id')
    if not user_id:
        flash("Please log in to add a resource.", "error")
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description', '')
        category = request.form.get('category')
        availability = request.form.get('availability')
        image = request.files.get('image')

        # Validate required fields
        if not title or not category or not availability:
            flash('All fields are required.', 'error')
            return redirect(url_for('new_resource'))

        # Validate date format (YYYY-MM-DD)
        try:
            datetime.strptime(availability, '%Y-%m-%d')
        except ValueError:
            flash('Invalid date format. Please use YYYY-MM-DD.', 'error')
            return redirect(url_for('new_resource'))

        # Validate and save the image
        images = None
        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            images = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image.save(images)
        elif image:
            flash('Invalid file type. Only PNG, JPG, and JPEG files are allowed.', 'error')
            return redirect(url_for('new_resource'))

        try:
            # Save the resource in the database (pass images if needed)
            create_resource(user_id, title, description, category, availability, images)
            flash('Resource added successfully!', 'success')
            return redirect(url_for('list_resources'))
        except Exception as e:
            app.logger.error(f"Error creating resource: {e}")
            flash('An error occurred. Please try again.', 'error')
            return redirect(url_for('new_resource'))

    return render_template('new_resource.html')



@app.route('/resources')
def list_resources():
    resources = get_all_resources()
    return render_template('list_resources.html', resources=resources)

@app.route('/resource/<int:id>')
def view_resource(id):
    resource = get_resource_by_id(id)
    if resource is None:
        flash("Resource not found", "error")
        return redirect(url_for('list_resources'))

    return render_template('view_resource.html', resource=resource)

@app.route('/resource/<int:id>/edit', methods=['GET', 'POST'])
def edit_resource(id):
    user_id = session.get('user_id')
    if user_id is None:
        flash("You must be logged in to edit resources.", "error")
        return redirect(url_for('login'))

    resource = get_resource_by_id(id)
    if resource is None:
        flash("Resource not found.", "error")
        return redirect(url_for('list_resources'))

    # Only allow the owner to edit the resource
    if resource['user_id'] != user_id:
        flash("You are not authorized to edit this resource.", "error")
        return redirect(url_for('list_resources'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form.get('description', '')
        category = request.form['category']
        availability = request.form['availability']

        update_resource(id, title, description, category, availability)
        flash("Resource updated successfully.", "success")
        return redirect(url_for('view_resource', id=id))

    return render_template('edit_resource.html', resource=resource)

@app.route('/resource/<int:id>/delete', methods=['POST'])
def delete_resource_route(id):
    user_id = session.get('user_id')
    if user_id is None:
        flash("You must be logged in to delete resources.", "error")
        return redirect(url_for('login'))

    resource = get_resource_by_id(id)
    if resource is None:
        flash("Resource not found.", "error")
        return redirect(url_for('list_resources'))

    # Only allow the owner to delete the resource
    if resource['user_id'] != user_id:
        flash("You are not authorized to delete this resource.", "error")
        return redirect(url_for('list_resources'))

    delete_resource(id)  # This calls the helper function
    flash("Resource deleted successfully.", "success")
    return redirect(url_for('list_resources'))




# Message Routes
# app.py

@app.route('/inbox')
def inbox():
    user_id = session.get('user_id')
    if not user_id:
        flash("Please log in to view your inbox.", "error")
        return redirect(url_for('login'))

    # Handle GET for search
    search_query = request.args.get('search_recipient', '').strip()
    recipients = []
    if search_query:
        recipients = get_db().execute(
            "SELECT id, name FROM users WHERE name LIKE ? LIMIT 10",
            (f"%{search_query}%",)
        ).fetchall()

    # Fetch conversations
    conversations = get_inbox(user_id)

    return render_template('inbox.html', conversations=conversations, recipients=recipients)


@app.route('/search_users', methods=['GET'])
def search_users():
    query = request.args.get('q', '')
    if not query:
        return jsonify([])

    users = get_db().execute(
        "SELECT id, name FROM users WHERE name LIKE ? LIMIT 10", (f"%{query}%",)
    ).fetchall()

    return jsonify([{'id': user['id'], 'name': user['name']} for user in users])


@app.route('/send_message/<int:receiver_id>', methods=['GET', 'POST'])
def send_message_route(receiver_id):  # Avoid conflict with helper function
    user_id = session.get('user_id')
    if not user_id:
        flash("Please log in to send a message.", "error")
        return redirect(url_for('login'))

    # Validate receiver exists
    if receiver_id <= 0:
        flash("Please select a valid recipient.", "error")
        return redirect(url_for('inbox'))

    receiver = get_user_by_id(receiver_id)
    if not receiver:
        flash("Recipient not found.", "error")
        return redirect(url_for('inbox'))

    if request.method == 'POST':
        content = request.form.get('content')
        if content:
            send_message(user_id, receiver_id, content)  # Helper function to save message
            flash("Message sent successfully!", "success")
            return redirect(url_for('conversation', user_id=receiver_id))
        else:
            flash("Message content cannot be empty.", "error")
            return redirect(url_for('conversation', user_id=receiver_id))

    return render_template('send_message.html', receiver=receiver)



@app.route('/conversation/<int:user_id>')
def conversation(user_id):
    sender_id = session.get('user_id')
    if not sender_id:
        flash("Please log in to view the conversation.", "error")
        return redirect(url_for('login'))

    receiver = get_user_by_id(user_id)
    if not receiver:
        flash("The user you are trying to message does not exist.", "error")
        return redirect(url_for('inbox'))

    messages = get_conversation(sender_id, user_id)
    return render_template(
        'conversation.html',
        messages=messages,
        receiver=receiver
    )




# spaces routes

@app.route('/spaces')
def list_spaces():
    spaces = get_all_spaces()
    return render_template('list_spaces.html', spaces=spaces)

@app.route('/space/<int:space_id>')
def view_space(space_id):
    space = get_space_by_id(space_id)
    return render_template('view_space.html', space=space)

@app.route('/space/new', methods=['GET', 'POST'])
def new_space():
    # Ensure user is logged in
    user_id = session.get('user_id')
    if not user_id:
        flash("Please log in to list a new community space.", "error")
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Gather form inputs
        name = request.form['name']
        description = request.form.get('description', '')
        location = request.form['location']
        availability = request.form['availability']

        # Validate required fields
        if not name or not location or not availability:
            flash("Name, location, and availability are required.", "error")
            return redirect(url_for('new_space'))

        # Validate availability format (YYYY-MM-DD)
        try:
            datetime.strptime(availability, '%Y-%m-%d')
        except ValueError:
            flash("Invalid availability date format. Please use YYYY-MM-DD.", "error")
            return redirect(url_for('new_space'))

        try:
            # Create the space in the database
            create_space(name, description, location, availability, user_id)
            flash("Space listed successfully!", "success")
            return redirect(url_for('list_spaces'))
        except Exception as e:
            app.logger.error(f"Error listing space: {e}")
            flash("An error occurred while listing the space. Please try again.", "error")
            return redirect(url_for('new_space'))

    return render_template('new_space.html')

#@app.route('/space/<int:space_id>/book', methods=['POST'])
#def book_space(space_id):
#    user_id = session.get('user_id')
    if not user_id:
        flash("Please log in to book a space.", "error")
        return redirect(url_for('login'))

    # Implement logic to handle booking (e.g., save booking in the database)
    flash("Space booked successfully!", "success")
    return redirect(url_for('view_space', space_id=space_id))

@app.route('/space/<int:space_id>/edit', methods=['GET', 'POST'])
def edit_space(space_id):
    user_id = session.get('user_id')
    if not user_id:
        flash("Please log in to edit spaces.", "error")
        return redirect(url_for('login'))

    space = get_space_by_id(space_id)
    if space is None:
        flash("Space not found.", "error")
        return redirect(url_for('list_spaces'))

    # Only allow the creator to edit the space
    if space['created_by'] != user_id:
        flash("You are not authorized to edit this space.", "error")
        return redirect(url_for('list_spaces'))

    if request.method == 'POST':
        name = request.form['name']
        description = request.form.get('description', '')
        location = request.form['location']
        availability = request.form['availability']

        # Update the space in the database
        db = get_db()
        db.execute(
            "UPDATE spaces SET name = ?, description = ?, location = ?, availability = ? WHERE space_id = ?",
            (name, description, location, availability, space_id)
        )
        db.commit()
        flash("Space updated successfully.", "success")
        return redirect(url_for('view_space', space_id=space_id))

    return render_template('edit_space.html', space=space)

@app.route('/space/<int:space_id>/delete', methods=['POST'])
def delete_space(space_id):
    user_id = session.get('user_id')
    if not user_id:
        flash("Please log in to delete spaces.", "error")
        return redirect(url_for('login'))

    space = get_space_by_id(space_id)
    if space is None:
        flash("Space not found.", "error")
        return redirect(url_for('list_spaces'))

    # Only allow the creator to delete the space
    if space['created_by'] != user_id:
        flash("You are not authorized to delete this space.", "error")
        return redirect(url_for('list_spaces'))

    # Delete the space
    db = get_db()
    db.execute("DELETE FROM spaces WHERE space_id = ?", (space_id,))
    db.commit()

    flash("Space deleted successfully.", "success")
    return redirect(url_for('list_spaces'))


# events routes

@app.route('/events')
def list_events():
    events = get_all_events()
    return render_template('list_events.html', events=events)

@app.route('/event/<int:event_id>')
def view_event(event_id):
    user_id = session.get('user_id')  # Get the logged-in user's ID
    if not user_id:
        flash("Please log in to view this event.", "error")
        return redirect(url_for('login'))

    # Fetch event details
    event = get_event_by_id(event_id)
    if not event:
        flash("Event not found.", "error")
        return redirect(url_for('list_events'))

    # Check if the user has already booked the event
    booked = get_db().execute(
        "SELECT 1 FROM event_bookings WHERE user_id = ? AND event_id = ?",
        (user_id, event_id)
    ).fetchone() is not None

    # Render the event with booking status
    return render_template('view_event.html', event=event, booked=booked)




from datetime import datetime

@app.route('/event/new', methods=['GET', 'POST'])
def new_event():
    # Ensure user is logged in
    user_id = session.get('user_id')
    if not user_id:
        flash("Please log in to create an event.", "error")
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Gather form inputs
        name = request.form.get('name')
        description = request.form.get('description', '')
        date = request.form.get('date')
        location = request.form.get('location')

        # Validate required fields
        if not name or not date or not location:
            flash("Name, date, and location are required to create an event.", "error")
            return redirect(url_for('new_event'))

        # Validate date format (YYYY-MM-DD)
        try:
            datetime.strptime(date, '%Y-%m-%d')
        except ValueError:
            flash("Invalid date format. Please use YYYY-MM-DD.", "error")
            return redirect(url_for('new_event'))

        try:
            # Create the event in the database
            create_event(name, description, date, location, user_id)
            flash("Event created successfully!", "success")
            return redirect(url_for('list_events'))
        except Exception as e:
            app.logger.error(f"Error creating event: {e}")
            flash("An error occurred while creating the event. Please try again.", "error")
            return redirect(url_for('new_event'))

    # Render the form to create a new event
    return render_template('new_event.html')


@app.route('/event/<int:event_id>/edit', methods=['GET', 'POST'])
def edit_event(event_id):
    user_id = session.get('user_id')
    if not user_id:
        flash("Please log in to edit events.", "error")
        return redirect(url_for('login'))

    event = get_event_by_id(event_id)
    if event is None:
        flash("Event not found.", "error")
        return redirect(url_for('list_events'))

    # Only allow the host to edit the event
    if event['hosted_by'] != user_id:
        flash("You are not authorized to edit this event.", "error")
        return redirect(url_for('list_events'))

    if request.method == 'POST':
        name = request.form['name']
        description = request.form.get('description', '')
        date = request.form['date']
        location = request.form['location']

        db = get_db()
        db.execute(
            "UPDATE events SET name = ?, description = ?, date = ?, location = ? WHERE event_id = ?",
            (name, description, date, location, event_id)
        )
        db.commit()

        flash("Event updated successfully.", "success")
        return redirect(url_for('view_event', event_id=event_id))

    return render_template('edit_event.html', event=event)




@app.route('/event/<int:event_id>/join', methods=['POST'])
def join_event(event_id):
    user_id = session.get('user_id')
    if not user_id:
        flash("Please log in to join an event.", "error")
        return redirect(url_for('login'))

    # Implement logic to handle joining the event (e.g., save attendee in the database)
    flash("Joined the event successfully!", "success")
    return redirect(url_for('view_event', event_id=event_id))

@app.route('/event/<int:event_id>/delete', methods=['POST'])
def delete_event(event_id):
    user_id = session.get('user_id')
    if not user_id:
        flash("Please log in to delete events.", "error")
        return redirect(url_for('login'))

    event = get_event_by_id(event_id)
    if not event:
        flash("Event not found.", "error")
        return redirect(url_for('list_events'))

    # Ensure the user is the host of the event
    if event['hosted_by'] != user_id:
        flash("You are not authorized to delete this event.", "error")
        return redirect(url_for('list_events'))

    # Delete the event
    db = get_db()
    db.execute("DELETE FROM events WHERE event_id = ?", (event_id,))
    db.commit()

    flash("Event deleted successfully.", "success")
    return redirect(url_for('list_events'))

@app.route('/event/<int:event_id>/book', methods=['POST'])
def book_event(event_id):
    user_id = session.get('user_id')
    if not user_id:
        flash("Please log in to book this event.", "error")
        return redirect(url_for('login'))

    # Logic to save the booking in the database
    try:
        db = get_db()
        db.execute(
            "INSERT INTO event_bookings (event_id, user_id) VALUES (?, ?)",
            (event_id, user_id)
        )
        db.commit()
        flash("Successfully booked the event!", "success")
    except sqlite3.IntegrityError:
        flash("You have already booked this event.", "error")
    except Exception as e:
        app.logger.error(f"Error booking event: {e}")
        flash("An error occurred while booking the event. Please try again.", "error")

    return redirect(url_for('view_event', event_id=event_id))

@app.route('/resource/<int:resource_id>/book', methods=['POST'])
def book_resource_route(resource_id):
    user_id = session.get('user_id')
    if not user_id:
        flash("Please log in to book this resource.", "error")
        return redirect(url_for('login'))

    # Check if the resource exists
    resource = get_resource_by_id(resource_id)
    if not resource:
        flash("Resource not found.", "error")
        return redirect(url_for('list_resources'))

    booking_date = datetime.now().strftime('%Y-%m-%d')

    try:
        book_resource(user_id, resource_id, booking_date)
        flash("Resource booked successfully!", "success")
    except Exception as e:
        app.logger.error(f"Error booking resource: {e}")
        flash("An error occurred while booking the resource. Please try again.", "error")

    return redirect(url_for('view_resource', id=resource_id))

@app.route('/space/<int:space_id>/book', methods=['POST'])
def book_space_route(space_id):
    user_id = session.get('user_id')
    if not user_id:
        flash("Please log in to book this space.", "error")
        return redirect(url_for('login'))

    # Check if the space exists
    space = get_space_by_id(space_id)
    if not space:
        flash("Space not found.", "error")
        return redirect(url_for('list_spaces'))

    booking_date = datetime.now().strftime('%Y-%m-%d')

    try:
        book_space(user_id, space_id, booking_date)
        flash("Space booked successfully!", "success")
    except Exception as e:
        app.logger.error(f"Error booking space: {e}")
        flash("An error occurred while booking the space. Please try again.", "error")

    return redirect(url_for('view_space', space_id=space_id))

@app.route('/event/<int:event_id>/book', methods=['POST'])
def book_event_route(event_id):
    user_id = session.get('user_id')  # Get the logged-in user's ID
    if not user_id:
        flash("Please log in to book this event.", "error")
        return redirect(url_for('login'))

    # Check if the event exists
    event = get_event_by_id(event_id)
    if not event:
        flash("Event not found.", "error")
        return redirect(url_for('list_events'))

    # Check if the user has already booked the event
    db = get_db()
    already_booked = db.execute(
        "SELECT 1 FROM event_bookings WHERE user_id = ? AND event_id = ?",
        (user_id, event_id)
    ).fetchone()

    if already_booked:
        flash("You have already booked this event.", "info")
        return redirect(url_for('view_event', event_id=event_id))

    # Book the event
    try:
        booking_date = datetime.now().strftime('%Y-%m-%d')
        book_event(user_id, event_id, booking_date)  # Call the helper function
        flash("Event booked successfully!", "success")
    except Exception as e:
        app.logger.error(f"Error booking event: {e}")
        flash("An error occurred while booking the event. Please try again.", "error")

    return redirect(url_for('view_event', event_id=event_id))

if __name__ == '__main__':
    app.run(debug=True)
