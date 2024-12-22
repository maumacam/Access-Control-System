from flask import Flask, render_template, redirect, url_for, request, flash
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Allowed file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Initialize the login manager
login_manager = LoginManager()
login_manager.init_app(app)

# User class
class User(UserMixin):
    def __init__(self, id, username, password_hash, profile_picture=None):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.profile_picture = profile_picture

    @staticmethod
    def get_user_by_username(username):
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ?', (username,))
        user_data = c.fetchone()
        conn.close()

        if user_data:
            return User(user_data[0], user_data[1], user_data[2], user_data[4])  # user_data[4] is profile_picture
        return None

    def update_profile(self, username, email, password_hash, profile_picture):
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute(''' 
            UPDATE users 
            SET username = ?, email = ?, password_hash = ?, profile_picture = ? 
            WHERE id = ? 
        ''', (username, email, password_hash, profile_picture, self.id))
        conn.commit()
        conn.close()

# Load user from database by user_id
@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user_data = c.fetchone()
    conn.close()

    if user_data:
        return User(user_data[0], user_data[1], user_data[2], user_data[4])  # user_data[4] is profile_picture
    return None

# Create database and tables if not exists
def create_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()

    # Create the users table with new columns: email and profile_picture
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT,
            profile_picture TEXT
        )
    ''')

    # Create the team table
    c.execute('''
        CREATE TABLE IF NOT EXISTS team (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            role TEXT NOT NULL
        )
    ''')

    # Add default team members
    c.execute('''
    INSERT OR IGNORE INTO team (id, name, role)
    VALUES
        (1, 'Angelo', 'Developer'),
        (2, 'Jamaica', 'Developer')
    ''')

    conn.commit()
    conn.close()

create_db()

# Home route
@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# About Us route
@app.route('/about')
def about():
    return render_template('about.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.get_user_by_username(username)

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            return "Invalid username or password"

    return render_template('login.html')

# Contact Us route
@app.route('/contact')
def contact():
    return render_template('contact.html')

# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Hash the password before storing it
        password_hash = generate_password_hash(password)

        # Insert the new user into the database
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('''
            INSERT INTO users (username, password_hash)
            VALUES (?, ?)
        ''', (username, password_hash))
        conn.commit()
        conn.close()

        return redirect(url_for('login'))

    return render_template('register.html')

# Dashboard route (only accessible when logged in)
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=current_user.username)

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        # Check if the current password is correct
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT password_hash FROM users WHERE id = ?', (current_user.id,))
        stored_password = c.fetchone()
        conn.close()

        if not stored_password or not check_password_hash(stored_password[0], current_password):
            flash('Current password is incorrect.', 'danger')
            return redirect(url_for('change_password'))

        # Validate the new password
        if new_password != confirm_password:
            flash('New password and confirm password do not match.', 'danger')
            return redirect(url_for('change_password'))

        # Hash the new password and update it in the database
        new_password_hash = generate_password_hash(new_password)
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('UPDATE users SET password_hash = ? WHERE id = ?', (new_password_hash, current_user.id))
        conn.commit()
        conn.close()

        flash('Your password has been changed successfully.', 'success')
        return redirect(url_for('dashboard'))  # Redirect to dashboard after success

    return render_template('change_password.html')

@app.route('/edit-profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        profile_picture = None

        # Check if a profile picture is uploaded
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join('static/uploads', filename)
                file.save(file_path)
                profile_picture = filename  # Store only the file name

        # If password is provided, hash it before saving
        if password:
            password_hash = generate_password_hash(password)
        else:
            password_hash = current_user.password_hash  # Retain the current password if not changing

        # Update the user profile in the database
        current_user.update_profile(username, email, password_hash, profile_picture)

        return redirect(url_for('dashboard'))

    return render_template('edit_profile.html')

# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
