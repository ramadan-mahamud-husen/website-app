from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import apology, login_required
import os
import re
import logging
from datetime import timedelta

# Configure application
app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///users.db")

# Security configurations
app.secret_key = os.urandom(24)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/")
@login_required
def index():
    """Dashboard page"""
    user_id = session.get("user_id")
    if not user_id:
        return redirect("/login")

    user = db.execute("SELECT first_name FROM users WHERE id = ?", user_id)

    if not user:
        flash("User not found. Please log in again.", "error")
        return redirect("/logout")

    name = user[0]["first_name"]
    return render_template("layout.html", name=name)

def validate_email(email):
    """Validate email format"""
    if not email or len(email) > 254:
        return False
    return bool(re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email))

def validate_password(password):
    """Validate password meets complexity requirements"""
    if len(password) < 8 or len(password) > 128:
        return False
    if not re.search(r'[A-Z]', password):  # At least one uppercase
        return False
    if not re.search(r'[a-z]', password):  # At least one lowercase
        return False
    if not re.search(r'\d', password):     # At least one number
        return False
    if not re.search(r'[@$!%*?&]', password):  # At least one special char
        return False
    return True

def validate_name(name):
    """Validate first name (letters only, min 2 chars, max 50)"""
    if not name or len(name) > 50:
        return False
    return bool(re.match(r'^[a-zA-Z]{2,}$', name))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            email = request.form.get('email', '').strip()
            password = request.form.get('password', '').strip()
            confirmation = request.form.get('confirmation', '').strip()
            first_name = request.form.get('First_name', '').strip()

            # Validate email
            if not email:
                return apology("Email is required", 400)
            if not validate_email(email):
                return apology("Please enter a valid email address", 400)

            # Check if email exists
            existing_user = db.execute("SELECT * FROM users WHERE email = ?", email)
            if existing_user:
                return apology("Email already registered", 400)

            # Validate password
            if not password:
                return apology("Password is required", 400)
            if not validate_password(password):
                return apology("Password must contain: 8+ characters, 1 uppercase, 1 lowercase, 1 number, 1 special character (@$!%*?&)", 400)

            # Confirm password
            if password != confirmation:
                return apology("Passwords do not match", 400)

            # Validate name
            if not first_name:
                return apology("First name is required", 400)
            if not validate_name(first_name):
                return apology("Name must be 2-50 letters only", 400)

            # Hash password and register user
            hashed_password = generate_password_hash(password)
            db.execute("INSERT INTO users (email, hash, first_name) VALUES (?, ?, ?)",
                      email, hashed_password, first_name)

            logger.info(f"New user registered: {email[:2]}...{email[-2:]}")
            flash("Registration successful! Please log in.", 'success')
            return redirect(url_for('login'))

        except Exception as e:
            logger.error(f"Registration error: {str(e)}")
            return apology("An error occurred during registration", 500)

    return render_template('register.html')

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    session.clear()

    if request.method == "POST":
        try:
            email = request.form.get("email", "").strip()
            password = request.form.get("password", "").strip()

            # Validate inputs
            if not email:
                return apology("Please provide email", 400)
            if not password:
                return apology("Please provide password", 400)

            # Query database (note we use 'hash' column instead of 'password')
            rows = db.execute("SELECT * FROM users WHERE email = ?", email)

            # Check if user exists and password is correct
            if len(rows) != 1 or not check_password_hash(rows[0]["hash"], password):
                return apology("Invalid email and/or password", 400)

            # Remember which user has logged in
            session["user_id"] = rows[0]["id"]
            session["name"] = rows[0]["first_name"]

            # Set permanent session if "remember me" is checked
            if request.form.get("remember"):
                session.permanent = True
                app.permanent_session_lifetime = timedelta(days=30)

            flash(f"Welcome back, {rows[0]['first_name']}!", "success")
            return redirect("/dashboard")

        except Exception as e:
            logger.error(f"Login error for {email}: {str(e)}")
            return apology("An error occurred during login", 500)

    else:
        return render_template("login.html")

@app.route("/ideas", methods=["GET", "POST"])
@login_required
def ideas():
    """Share and view ideas"""
    if request.method == "POST":
        title = request.form.get("title")
        body = request.form.get("body")
        if not title or not body:
            return apology("Both title and body are required", 400)

        db.execute(
            "INSERT INTO ideas (user_id, title, body) VALUES (?, ?, ?)",
            session["user_id"],
            title,
            body
        )
        flash("Your idea has been shared!")
        return redirect("/ideas")
    else:
        ideas = db.execute(
            "SELECT ideas.title, ideas.body, users.first_name, ideas.timestamp FROM ideas "
            "JOIN users ON ideas.user_id = users.id ORDER BY ideas.timestamp DESC"
        )
        return render_template("ideas.html", ideas=ideas)

@app.route("/take-quizzes")
@login_required
def take_quizzes():
    """Take Quizzes Page with Subjects and Units"""
    subjects = {
        "Physics": [
            {"unit": "Unit 1: Kinematics", "test_link": "https://www.khanacademy.org/science/physics/one-dimensional-motion"},
            {"unit": "Unit 2: Newton's Laws of Motion", "test_link": "https://www.khanacademy.org/science/physics/forces-newtons-laws"},
            {"unit": "Unit 3: Work, Energy, and Power", "test_link": "https://www.khanacademy.org/science/physics/work-and-energy"},
            {"unit": "Unit 4: Momentum and Collisions", "test_link": "https://www.khanacademy.org/science/physics/momentum-and-collisions"},
            {"unit": "Unit 5: Circular Motion and Gravitation", "test_link": "https://www.khanacademy.org/science/physics/circular-motion"},
            {"unit": "Unit 6: Waves and Sound", "test_link": "https://www.khanacademy.org/science/physics/mechanical-waves-and-sound"},
            {"unit": "Unit 7: Optics - Light and Reflection", "test_link": "https://www.khanacademy.org/science/physics/geometric-optics"},
            {"unit": "Unit 8: Thermodynamics", "test_link": "https://www.khanacademy.org/science/physics/thermodynamics"},
            {"unit": "Unit 9: Electricity and Circuits", "test_link": "https://www.khanacademy.org/science/physics/circuits-topic"},
            {"unit": "Unit 10: Magnetism", "test_link": "https://www.khanacademy.org/science/physics/magnetic-forces-and-magnetic-fields"},
            {"unit": "Unit 11: Quantum Mechanics", "test_link": "https://www.khanacademy.org/science/physics/quantum-physics"},
            {"unit": "Unit 12: Special Relativity", "test_link": "https://www.khanacademy.org/science/physics/special-relativity"}
        ],
        # ... (keep the rest of your subjects data)
    }

    selected_subject = request.args.get("subject")

    if selected_subject and selected_subject in subjects:
        units = subjects[selected_subject]
        return render_template("take-quizzes.html", subjects=None, units=units, subject=selected_subject)

    return render_template("take-quizzes.html", subjects=subjects, units=None, subject=None)

@app.route('/leaderboard')
def leaderboard():
    """Render the board page."""
    return render_template('leaderboard.html')

@app.route('/dashboard')
def dashboard():
    name = session.get("name")
    return render_template('dashboard.html', name=name)

@app.route("/logout")
def logout():
    """Log user out"""
    session.clear()
    return redirect("/login")

if __name__ == '__main__':
    app.run(debug=True)
