import os
import re
from functools import wraps
from datetime import datetime, timedelta, time, date
from dotenv import load_dotenv

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    jsonify,
    make_response,
    get_flashed_messages,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import CheckConstraint
from twilio.rest import Client
from flask_apscheduler import APScheduler

# ==================== CONFIGURATION ====================

load_dotenv()


class Config:
    """Base configuration"""

    # Flask settings
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")

    # Database settings
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL", "mysql+pymysql://root:password@localhost:3306/volunteer_db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Session settings for authentication
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
    SESSION_COOKIE_SECURE = False  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    # Twilio SMS settings
    TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "")
    TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "")
    TWILIO_PHONE_NUMBER = os.getenv("TWILIO_PHONE_NUMBER", "")

    # APScheduler settings
    SCHEDULER_API_ENABLED = True
    SCHEDULER_TIMEZONE = "UTC"
    JOBS = [
        {
            "id": "event_reminder_job",
            "func": "app:check_and_send_event_reminders",
            "trigger": "interval",
            "minutes": 30,
        }
    ]


class DevelopmentConfig(Config):
    """Development configuration"""

    DEBUG = True
    TESTING = False


class TestingConfig(Config):
    """Testing configuration"""

    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"


class ProductionConfig(Config):
    """Production configuration"""

    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True


# Get active configuration based on environment
config_name = os.getenv("FLASK_ENV", "development")
if config_name == "production":
    current_config = ProductionConfig
elif config_name == "testing":
    current_config = TestingConfig
else:
    current_config = DevelopmentConfig


# ==================== DATABASE MODELS ====================

db = SQLAlchemy()


class User(db.Model):
    """User model for both Organizations and Volunteers"""

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(255), nullable=False)  # For volunteers
    phone = db.Column(db.String(20), nullable=True)  # For volunteers
    role = db.Column(db.Enum("organization", "volunteer"), nullable=False)

    # Organization-specific fields
    organization_name = db.Column(db.String(255), nullable=True)  # For organizations
    description = db.Column(db.Text, nullable=True)  # For organizations
    location = db.Column(db.String(255), nullable=True)  # For organizations

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    events = db.relationship(
        "Event", backref="organization", lazy=True, foreign_keys="Event.organization_id"
    )
    registrations = db.relationship(
        "Registration",
        backref="volunteer",
        lazy=True,
        foreign_keys="Registration.volunteer_id",
    )

    def set_password(self, password):
        """Hash and set password"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Check if password matches hash"""
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        """Convert user to dictionary"""
        return {
            "id": self.id,
            "email": self.email,
            "name": self.name,
            "role": self.role,
            "phone": self.phone,
            "organization_name": self.organization_name,
            "created_at": self.created_at.isoformat(),
        }


class Event(db.Model):
    """Event model for volunteer opportunities"""

    __tablename__ = "events"

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    date = db.Column(db.Date, nullable=False)
    start_time = db.Column(db.Time, nullable=False)
    end_time = db.Column(db.Time, nullable=False)
    location_text = db.Column(db.String(255), nullable=False)
    google_maps_link = db.Column(db.String(500), nullable=True)
    required_volunteers = db.Column(db.Integer, nullable=False, default=5)
    registered_volunteers = db.Column(db.Integer, default=0)
    status = db.Column(db.Enum("Open", "Full"), default="Open")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    registrations = db.relationship(
        "Registration", backref="event", lazy=True, cascade="all, delete-orphan"
    )

    def update_status(self):
        """Update event status based on registered volunteer count"""
        if self.registered_volunteers >= self.required_volunteers:
            self.status = "Full"
        else:
            self.status = "Open"
        return self.status

    def can_register(self, volunteer_id):
        """Check if volunteer can register for this event"""
        # Check if volunteer already registered
        existing = Registration.query.filter_by(
            event_id=self.id, volunteer_id=volunteer_id
        ).first()

        if existing:
            return False, "Already registered for this event"

        # Check if event is full
        if self.status == "Full":
            return False, "Event is full"

        # Check for time conflict
        volunteer = User.query.get(volunteer_id)
        if volunteer:
            conflicting = (
                db.session.query(Event)
                .join(Registration, Event.id == Registration.event_id)
                .filter(
                    Registration.volunteer_id == volunteer_id,
                    Event.date == self.date,
                    Event.start_time < self.end_time,
                    Event.end_time > self.start_time,
                )
                .first()
            )

            if conflicting:
                return False, "Time conflict with another event"

        return True, "Can register"

    def to_dict(self):
        """Convert event to dictionary"""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "date": self.date.isoformat(),
            "start_time": str(self.start_time),
            "end_time": str(self.end_time),
            "location_text": self.location_text,
            "required_volunteers": self.required_volunteers,
            "registered_volunteers": self.registered_volunteers,
            "status": self.status,
        }


class Registration(db.Model):
    """Registration model for volunteer event sign-ups"""

    __tablename__ = "registrations"

    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey("events.id"), nullable=False)
    volunteer_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    registered_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Unique constraint - volunteer can only register once per event
    __table_args__ = (
        db.UniqueConstraint("event_id", "volunteer_id", name="unique_event_volunteer"),
    )

    def to_dict(self):
        """Convert registration to dictionary"""
        return {
            "id": self.id,
            "event_id": self.event_id,
            "volunteer_id": self.volunteer_id,
            "registered_at": self.registered_at.isoformat(),
        }


# ==================== UTILITY FUNCTIONS & DECORATORS ====================


def organization_required(f):
    """
    Decorator to require organization role
    Redirects to login if not authenticated or user is not an organization
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))

        user = User.query.get(session["user_id"])

        if not user or user.role != "organization":
            flash(
                "You must be logged in as an organization to access this page.",
                "error",
            )
            return redirect(url_for("login"))

        return f(*args, **kwargs)

    return decorated_function


def volunteer_required(f):
    """
    Decorator to require volunteer role
    Redirects to login if not authenticated or user is not a volunteer
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))

        user = User.query.get(session["user_id"])

        if not user or user.role != "volunteer":
            flash("You must be logged in as a volunteer to access this page.", "error")
            return redirect(url_for("login"))

        return f(*args, **kwargs)

    return decorated_function


def login_required(f):
    """
    Decorator to require authentication
    Redirects to login if not authenticated
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))

        user = User.query.get(session["user_id"])

        if not user:
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))

        return f(*args, **kwargs)

    return decorated_function


def get_current_user():
    """
    Get the current authenticated user from session
    Returns None if not authenticated
    """
    if "user_id" in session:
        return User.query.get(session["user_id"])
    return None


def validate_email(email):
    """
    Validate email format
    Returns True if valid, False otherwise
    """
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(pattern, email) is not None


def validate_password(password):
    """
    Validate password strength
    Returns (is_valid, message)
    """
    if len(password) < 6:
        return False, "Password must be at least 6 characters long"
    if not any(char.isdigit() for char in password):
        return False, "Password must contain at least one number"
    if not any(char.isupper() for char in password):
        return False, "Password must contain at least one uppercase letter"
    return True, "Password is valid"


def validate_phone(phone):
    """
    Validate phone number format
    Returns True if valid, False otherwise
    """
    pattern = r"^[\d\s\-\+\(\)]{10,}$"
    return re.match(pattern, phone) is not None


def validate_required_fields(data, required_fields):
    """
    Validate that all required fields are present and non-empty
    Returns (is_valid, message)
    """
    missing = [field for field in required_fields if not data.get(field, "").strip()]

    if missing:
        return False, f'Missing required fields: {", ".join(missing)}'

    return True, "All required fields present"


def init_db(app):
    """
    Initialize database
    """
    with app.app_context():
        # Create all tables
        db.create_all()


# ==================== SMS NOTIFICATION UTILITIES ====================


def send_sms(phone_number, message):
    """
    Send SMS notification to user via Twilio

    Args:
        phone_number: Recipient's phone number
        message: SMS message content

    Returns:
        dict: {'success': True/False, 'message': status message, 'sid': message_id if successful}
    """
    try:
        # Check if Twilio credentials are configured
        if (
            not app.config["TWILIO_ACCOUNT_SID"]
            or not app.config["TWILIO_AUTH_TOKEN"]
            or not app.config["TWILIO_PHONE_NUMBER"]
        ):
            return {
                "success": False,
                "message": "SMS service not configured. Please set Twilio credentials in environment variables.",
            }

        # Initialize Twilio client
        client = Client(
            app.config["TWILIO_ACCOUNT_SID"], app.config["TWILIO_AUTH_TOKEN"]
        )

        # Send SMS
        msg = client.messages.create(
            body=message, from_=app.config["TWILIO_PHONE_NUMBER"], to=phone_number
        )

        return {"success": True, "message": "SMS sent successfully", "sid": msg.sid}

    except Exception as e:
        print(f"Error sending SMS: {str(e)}")
        return {"success": False, "message": f"Failed to send SMS: {str(e)}"}


def send_registration_confirmation_sms(user, event):
    """
    Send registration confirmation SMS to volunteer

    Args:
        user: User object (volunteer)
        event: Event object registered for

    Returns:
        dict: Result of SMS send operation
    """
    if not user.phone:
        return {"success": False, "message": "User phone number not available"}

    message = f"Great! You've registered for '{event.title}' on {event.date.strftime('%B %d, %Y')} at {event.start_time.strftime('%I:%M %p')}. "
    message += f"Location: {event.location_text}. See you there!"

    return send_sms(user.phone, message)


def send_event_reminder_sms(event):
    """
    Send reminder SMS to all registered volunteers for an event
    Called when event is within 12 hours

    Args:
        event: Event object

    Returns:
        dict: Summary of SMS sending results
    """
    registrations = Registration.query.filter_by(event_id=event.id).all()
    sent_count = 0
    failed_count = 0

    for registration in registrations:
        volunteer = User.query.get(registration.volunteer_id)
        if not volunteer or not volunteer.phone:
            failed_count += 1
            continue

        message = f"⏰ Reminder: Your event '{event.title}' is coming up soon! "
        message += f"Date: {event.date.strftime('%B %d, %Y')} at {event.start_time.strftime('%I:%M %p')}. "
        message += f"Location: {event.location_text}. Be prepared and see you there!"

        result = send_sms(volunteer.phone, message)
        if result["success"]:
            sent_count += 1
        else:
            failed_count += 1

    return {
        "event_id": event.id,
        "event_title": event.title,
        "sent_count": sent_count,
        "failed_count": failed_count,
    }


def check_and_send_event_reminders():
    """
    Check for events within 12 hours and send SMS reminders
    This function is called periodically by the scheduler
    """
    try:
        with app.app_context():
            # Get current time
            now = datetime.utcnow()
            # Calculate 12 hours from now
            reminder_time = now + timedelta(hours=12)

            # Find events that start within the next 12 hours and haven't been reminded
            events = Event.query.filter(
                Event.date == now.date(),
                Event.start_time <= reminder_time.time(),
                Event.start_time > now.time(),
            ).all()

            # Also check events starting tomorrow within first 12 hours
            tomorrow = now + timedelta(days=1)
            tomorrow_events = Event.query.filter(
                Event.date == tomorrow.date(), Event.start_time <= time(12, 0)
            ).all()

            events.extend(tomorrow_events)

            results = []
            for event in events:
                # Only send if event has registered volunteers
                if event.registered_volunteers > 0:
                    result = send_event_reminder_sms(event)
                    results.append(result)

            if results:
                print(f"✓ Event reminders sent: {len(results)} event(s)")
                for result in results:
                    print(
                        f"  - {result['event_title']}: {result['sent_count']} sent, {result['failed_count']} failed"
                    )

            return results

    except Exception as e:
        print(f"Error in check_and_send_event_reminders: {str(e)}")
        return []


class DatabaseHelper:
    """Helper class for common database operations"""

    @staticmethod
    def user_exists(email):
        """Check if user with email exists"""
        return User.query.filter_by(email=email).first() is not None

    @staticmethod
    def get_user_by_email(email):
        """Get user by email"""
        return User.query.filter_by(email=email).first()

    @staticmethod
    def get_organization_events(org_id):
        """Get all events for an organization"""
        return Event.query.filter_by(organization_id=org_id).all()

    @staticmethod
    def get_volunteer_registrations(volunteer_id):
        """Get all registrations for a volunteer"""
        registrations = Registration.query.filter_by(volunteer_id=volunteer_id).all()
        events = [Event.query.get(reg.event_id) for reg in registrations]
        return list(zip(registrations, events))

    @staticmethod
    def get_all_events():
        """Get all events"""
        return Event.query.all()


# ==================== FLASK APP INITIALIZATION ====================

# Initialize Flask app
app = Flask(__name__, static_folder="static", template_folder="templates")
app.config.from_object(current_config)

# Initialize extensions
db.init_app(app)

# Initialize scheduler for sending event reminders
scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()

# Schedule event reminder checks every 30 minutes
scheduler.add_job(
    func=check_and_send_event_reminders,
    trigger="interval",
    minutes=30,
    id="event_reminder_job",
    name="Check and send event reminders",
    replace_existing=True,
)


# ==================== CONTEXT PROCESSORS ====================


@app.context_processor
def inject_current_user():
    """Inject current user into all templates"""
    return dict(current_user=get_current_user())


@app.context_processor
def inject_config():
    """Inject config into all templates"""
    return dict(config=app.config)


# ==================== AUTHENTICATION ROUTES ====================


@app.route("/signup", methods=["GET", "POST"])
def signup():
    """
    Handle user registration for both volunteers and organizations
    GET: Show signup form
    POST: Process signup
    """
    if request.method == "GET":
        user_type = request.args.get("type", "volunteer")
        return render_template("signup.html", user_type=user_type)

    # POST request
    user_type = request.form.get("user_type", "volunteer").strip().lower()

    # Validate user type
    if user_type not in ["volunteer", "organization"]:
        flash("Invalid user type", "error")
        return redirect(url_for("signup"))

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    password_confirm = request.form.get("password_confirm", "")

    # Validate email
    if not email or not validate_email(email):
        flash("Invalid email address", "error")
        return redirect(url_for("signup", type=user_type))

    # Check if email already exists
    if DatabaseHelper.user_exists(email):
        flash("Email already registered", "error")
        return redirect(url_for("signup", type=user_type))

    # Validate password
    is_valid, message = validate_password(password)
    if not is_valid:
        flash(message, "error")
        return redirect(url_for("signup", type=user_type))

    # Check password confirmation
    if password != password_confirm:
        flash("Passwords do not match", "error")
        return redirect(url_for("signup", type=user_type))

    # Process volunteer registration
    if user_type == "volunteer":
        required_fields = ["name", "phone"]
        is_valid, message = validate_required_fields(request.form, required_fields)
        if not is_valid:
            flash(message, "error")
            return redirect(url_for("signup", type="volunteer"))

        name = request.form.get("name", "").strip()
        phone = request.form.get("phone", "").strip()

        if not validate_phone(phone):
            flash("Invalid phone number", "error")
            return redirect(url_for("signup", type="volunteer"))

        user = User(email=email, name=name, phone=phone, role="volunteer")

    # Process organization registration
    else:
        required_fields = ["organization_name", "description", "location"]
        is_valid, message = validate_required_fields(request.form, required_fields)
        if not is_valid:
            flash(message, "error")
            return redirect(url_for("signup", type="organization"))

        organization_name = request.form.get("organization_name", "").strip()
        description = request.form.get("description", "").strip()
        location = request.form.get("location", "").strip()

        user = User(
            email=email,
            name=organization_name,  # For consistency
            organization_name=organization_name,
            description=description,
            location=location,
            role="organization",
        )

    # Set password and save user
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    flash(f"Account created successfully! Please log in.", "success")
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Handle user login with JWT token creation
    GET: Show login form
    POST: Process login
    """
    if request.method == "GET":
        return render_template("login.html")

    # POST request
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    if not email or not password:
        flash("Email and password are required", "error")
        return redirect(url_for("login"))

    # Find user by email
    user = DatabaseHelper.get_user_by_email(email)

    if not user or not user.check_password(password):
        flash("Invalid email or password", "error")
        return redirect(url_for("login"))

    # Store user in session
    session["user_id"] = user.id
    session.permanent = True

    flash(f"Welcome back, {user.name}!", "success")

    # Redirect based on role
    if user.role == "organization":
        return redirect(url_for("org_dashboard"))
    else:
        return redirect(url_for("volunteer_dashboard"))


@app.route("/logout", methods=["GET"])
def logout():
    """
    Handle user logout by clearing session
    """
    session.clear()
    flash("You have been logged out successfully", "success")
    return redirect(url_for("login"))


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    """
    View and update user profile
    """
    current_user = get_current_user()

    if request.method == "POST":
        # Get form data
        name = request.form.get("name", "").strip()
        phone = request.form.get("phone", "").strip()
        current_password = request.form.get("current_password", "").strip()
        new_password = request.form.get("new_password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()

        # Validate required fields
        if not name:
            flash("Name is required", "error")
            return redirect(url_for("profile"))

        # Update basic information
        current_user.name = name
        if phone:
            current_user.phone = phone

        # Handle organization-specific fields
        if current_user.role == "organization":
            organization_name = request.form.get("organization_name", "").strip()
            description = request.form.get("description", "").strip()
            location = request.form.get("location", "").strip()

            if not organization_name:
                flash("Organization name is required", "error")
                return redirect(url_for("profile"))

            current_user.organization_name = organization_name
            current_user.description = description
            current_user.location = location

        # Handle password change
        if current_password or new_password or confirm_password:
            if not current_password:
                flash("Current password is required to change password", "error")
                return redirect(url_for("profile"))

            if not new_password or not confirm_password:
                flash("New password and confirmation are required", "error")
                return redirect(url_for("profile"))

            if new_password != confirm_password:
                flash("New password and confirmation do not match", "error")
                return redirect(url_for("profile"))

            # Validate current password
            if not current_user.check_password(current_password):
                flash("Current password is incorrect", "error")
                return redirect(url_for("profile"))

            # Validate new password strength
            is_valid, message = validate_password(new_password)
            if not is_valid:
                flash(message, "error")
                return redirect(url_for("profile"))

            # Update password
            current_user.set_password(new_password)
            flash("Password changed successfully", "success")

        # Save changes
        db.session.commit()
        flash("Profile updated successfully", "success")
        return redirect(url_for("profile"))

    return render_template("profile.html", current_user=current_user)


@app.route("/refresh", methods=["POST"])
def refresh():
    """
    Refresh session (not needed with session-based auth, but kept for compatibility)
    """
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    user = User.query.get(session["user_id"])
    if not user:
        session.clear()
        return jsonify({"error": "User not found"}), 401

    return jsonify({"success": True}), 200


# ==================== EVENT MANAGEMENT ROUTES ====================


@app.route("/events", methods=["GET"])
def list_events():
    """
    List all available events
    Volunteers see all open events, organizations see their events
    """
    current_user = get_current_user()

    # Get all events ordered by date
    events = Event.query.order_by(Event.date, Event.start_time).all()

    # For volunteers, add registration info
    volunteer_registrations = set()
    if current_user and current_user.role == "volunteer":
        registrations = Registration.query.filter_by(volunteer_id=current_user.id).all()
        volunteer_registrations = {reg.event_id for reg in registrations}

    return render_template(
        "events.html",
        events=events,
        current_user=current_user,
        volunteer_registrations=volunteer_registrations,
    )


@app.route("/event/<int:event_id>", methods=["GET"])
def event_detail(event_id):
    """
    Show event details
    """
    event = Event.query.get_or_404(event_id)
    organization = User.query.get(event.organization_id)
    current_user = get_current_user()

    # Check if current user is registered
    is_registered = False
    if current_user and current_user.role == "volunteer":
        is_registered = (
            Registration.query.filter_by(
                event_id=event_id, volunteer_id=current_user.id
            ).first()
            is not None
        )

    return render_template(
        "event_detail.html",
        event=event,
        organization=organization,
        current_user=current_user,
        is_registered=is_registered,
    )


@app.route("/event/<int:event_id>/register", methods=["POST"])
@volunteer_required
def register_event(event_id):
    """
    Register a volunteer for an event
    """
    event = Event.query.get_or_404(event_id)
    current_user = get_current_user()

    # Check if volunteer can register
    can_register, message = event.can_register(current_user.id)

    if not can_register:
        flash(message, "error")
        return redirect(url_for("event_detail", event_id=event_id))

    # Create registration
    registration = Registration(event_id=event_id, volunteer_id=current_user.id)

    event.registered_volunteers += 1
    event.update_status()

    db.session.add(registration)
    db.session.commit()

    # Send SMS confirmation silently (no messages shown to user)
    send_registration_confirmation_sms(current_user, event)

    # Show registration success message only
    flash(f"Successfully registered for {event.title}!", "success")

    return redirect(url_for("event_detail", event_id=event_id))


@app.route("/event/<int:event_id>/unregister", methods=["POST"])
@volunteer_required
def unregister_event(event_id):
    """
    Unregister a volunteer from an event
    """
    event = Event.query.get_or_404(event_id)
    current_user = get_current_user()

    # Find and delete registration
    registration = Registration.query.filter_by(
        event_id=event_id, volunteer_id=current_user.id
    ).first()

    if not registration:
        flash("You are not registered for this event", "error")
        return redirect(url_for("event_detail", event_id=event_id))

    # Update event
    event.registered_volunteers -= 1
    event.update_status()

    db.session.delete(registration)
    db.session.commit()

    flash(f"Successfully unregistered from {event.title}", "success")
    return redirect(url_for("event_detail", event_id=event_id))


@app.route("/org/dashboard", methods=["GET"])
@organization_required
def org_dashboard():
    """
    Organization dashboard showing their events
    """
    current_user = get_current_user()
    events = (
        Event.query.filter_by(organization_id=current_user.id)
        .order_by(Event.date, Event.start_time)
        .all()
    )

    return render_template(
        "org_dashboard.html", events=events, current_user=current_user
    )


@app.route("/org/create-event", methods=["GET", "POST"])
@organization_required
def create_event():
    """
    Create a new event
    GET: Show form
    POST: Create event
    """
    if request.method == "GET":
        return render_template("create_event.html")

    # POST request
    current_user = get_current_user()

    required_fields = [
        "title",
        "description",
        "date",
        "start_time",
        "end_time",
        "location_text",
        "required_volunteers",
    ]
    is_valid, message = validate_required_fields(request.form, required_fields)

    if not is_valid:
        flash(message, "error")
        return redirect(url_for("create_event"))

    # Parse and validate inputs
    try:
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        date_str = request.form.get("date", "")
        start_time_str = request.form.get("start_time", "")
        end_time_str = request.form.get("end_time", "")
        location_text = request.form.get("location_text", "").strip()
        google_maps_link = request.form.get("google_maps_link", "").strip()
        required_volunteers = int(request.form.get("required_volunteers", 1))

        # Validate required_volunteers
        if required_volunteers < 1:
            flash("Required volunteers must be at least 1", "error")
            return redirect(url_for("create_event"))

        # Parse date and time
        date_obj = datetime.strptime(date_str, "%Y-%m-%d").date()
        start_time_obj = datetime.strptime(start_time_str, "%H:%M").time()
        end_time_obj = datetime.strptime(end_time_str, "%H:%M").time()

        # Validate times
        if start_time_obj >= end_time_obj:
            flash("Start time must be before end time", "error")
            return redirect(url_for("create_event"))

        if date_obj < datetime.utcnow().date():
            flash("Event date cannot be in the past", "error")
            return redirect(url_for("create_event"))

    except ValueError:
        flash("Invalid date or time format", "error")
        return redirect(url_for("create_event"))

    # Create event
    event = Event(
        organization_id=current_user.id,
        title=title,
        description=description,
        date=date_obj,
        start_time=start_time_obj,
        end_time=end_time_obj,
        location_text=location_text,
        google_maps_link=google_maps_link if google_maps_link else None,
        required_volunteers=required_volunteers,
    )

    db.session.add(event)
    db.session.commit()

    flash(f'Event "{title}" created successfully!', "success")
    return redirect(url_for("org_dashboard"))


@app.route("/org/edit-event/<int:event_id>", methods=["GET", "POST"])
@organization_required
def edit_event(event_id):
    """
    Edit an existing event
    GET: Show form
    POST: Update event
    """
    event = Event.query.get_or_404(event_id)
    current_user = get_current_user()

    # Check if current user owns this event
    if event.organization_id != current_user.id:
        flash("You do not have permission to edit this event", "error")
        return redirect(url_for("org_dashboard"))

    if request.method == "GET":
        return render_template("edit_event.html", event=event)

    # POST request
    try:
        event.title = request.form.get("title", "").strip()
        event.description = request.form.get("description", "").strip()

        date_str = request.form.get("date", "")
        start_time_str = request.form.get("start_time", "")
        end_time_str = request.form.get("end_time", "")

        event.date = datetime.strptime(date_str, "%Y-%m-%d").date()
        event.start_time = datetime.strptime(start_time_str, "%H:%M").time()
        event.end_time = datetime.strptime(end_time_str, "%H:%M").time()

        if event.start_time >= event.end_time:
            flash("Start time must be before end time", "error")
            return redirect(url_for("edit_event", event_id=event_id))

        event.location_text = request.form.get("location_text", "").strip()
        event.google_maps_link = (
            request.form.get("google_maps_link", "").strip() or None
        )

        required_volunteers = int(request.form.get("required_volunteers", 1))
        if required_volunteers < 1:
            flash("Required volunteers must be at least 1", "error")
            return redirect(url_for("edit_event", event_id=event_id))

        event.required_volunteers = required_volunteers
        event.update_status()

        db.session.commit()

        flash(f'Event "{event.title}" updated successfully!', "success")
        return redirect(url_for("org_dashboard"))

    except ValueError:
        flash("Invalid date or time format", "error")
        return redirect(url_for("edit_event", event_id=event_id))


@app.route("/org/delete-event/<int:event_id>", methods=["POST"])
@organization_required
def delete_event(event_id):
    """
    Delete an event (with confirmation)
    """
    event = Event.query.get_or_404(event_id)
    current_user = get_current_user()

    # Check if current user owns this event
    if event.organization_id != current_user.id:
        flash("You do not have permission to delete this event", "error")
        return redirect(url_for("org_dashboard"))

    event_title = event.title
    db.session.delete(event)
    db.session.commit()

    flash(f'Event "{event_title}" deleted successfully!', "success")
    return redirect(url_for("org_dashboard"))


@app.route("/volunteer/dashboard", methods=["GET"])
@volunteer_required
def volunteer_dashboard():
    """
    Volunteer dashboard showing upcoming events
    """
    current_user = get_current_user()

    # Get all upcoming events
    events = (
        Event.query.filter(Event.date >= datetime.utcnow().date())
        .order_by(Event.date, Event.start_time)
        .all()
    )

    # Get volunteer's registrations
    registrations = Registration.query.filter_by(volunteer_id=current_user.id).all()
    registered_event_ids = {reg.event_id for reg in registrations}

    return render_template(
        "volunteer_dashboard.html",
        events=events,
        current_user=current_user,
        registered_event_ids=registered_event_ids,
    )


@app.route("/volunteer/my-registrations", methods=["GET"])
@volunteer_required
def my_registrations():
    """
    Show volunteer's current event registrations
    """
    current_user = get_current_user()

    registrations = (
        Registration.query.filter_by(volunteer_id=current_user.id)
        .order_by(Registration.registered_at.desc())
        .all()
    )

    events = []
    for reg in registrations:
        event = Event.query.get(reg.event_id)
        if event:
            events.append(
                {
                    "registration": reg,
                    "event": event,
                    "organization": User.query.get(event.organization_id),
                }
            )

    return render_template(
        "my_registrations.html",
        events=events,
        current_user=current_user,
    )


# ==================== HOME ROUTES ====================


@app.route("/", methods=["GET"])
def index():
    """Landing page - redirect based on authentication"""
    current_user = get_current_user()

    if current_user:
        if current_user.role == "organization":
            return redirect(url_for("org_dashboard"))
        else:
            return redirect(url_for("volunteer_dashboard"))

    return render_template("index.html")


@app.route("/about", methods=["GET"])
def about():
    """About page"""
    return render_template("about.html")


# ==================== ERROR HANDLERS ====================


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return render_template("404.html"), 404


@app.errorhandler(403)
def forbidden(error):
    """Handle 403 errors"""
    flash("You do not have permission to access this page.", "error")
    return redirect(url_for("index")), 403


@app.errorhandler(500)
def server_error(error):
    """Handle 500 errors"""
    flash("An internal server error occurred. Please try again.", "error")
    return render_template("500.html"), 500


# ==================== JWT ERROR HANDLERS ====================


# ==================== APPLICATION STARTUP ====================


@app.before_request
def before_request():
    """Run before each request"""
    session.permanent = True
    app.permanent_session_lifetime = app.config["PERMANENT_SESSION_LIFETIME"]


@app.teardown_appcontext
def shutdown_session(exception=None):
    """Clean up session after request"""
    pass


if __name__ == "__main__":
    with app.app_context():
        init_db(app)
        app.run(host="localhost", port=5000, debug=True, use_reloader=True)
