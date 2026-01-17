# Volunteer Coordination Platform - README

A complete, production-ready web application for managing volunteer events and registrations.

## 📋 Features

✅ **Role-Based Access Control**
- Separate dashboards for Organizations and Volunteers
- Only organizations can create/edit/delete events
- Only volunteers can register for events

✅ **JWT Authentication**
- Access & refresh tokens
- HTTP-only cookies for security
- Secure password hashing with Werkzeug

✅ **Event Management**
- Organizations create, edit, and delete events
- Full event details: date, time, location, description
- Google Maps integration
- Volunteer requirement tracking

✅ **Smart Registration System**
- Prevent duplicate registrations
- Automatic time conflict detection
- Real-time event status updates (Open/Full)
- Unregister functionality

✅ **Modern UI**
- Responsive design (mobile, tablet, desktop)
- Clean CSS styling
- Flash messages for user feedback
- Progress bars for registrations

## 🛠️ Tech Stack

- **Backend**: Python Flask
- **ORM**: Flask-SQLAlchemy (modular design for easy migration)
- **Database**: MySQL
- **Authentication**: JWT with Flask-JWT-Extended
- **Frontend**: HTML5, CSS3, Vanilla JavaScript, Jinja2
- **Security**: Werkzeug password hashing

## 📦 Installation

### 1. Prerequisites

- Python 3.8+
- MySQL Server (running)
- pip (Python package manager)

### 2. Clone or Extract Project

```bash
cd Volunteer2
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Database Setup

Create a MySQL database:

```sql
CREATE DATABASE volunteer_db;
```

### 5. Configure Environment

Edit the `.env` file with your MySQL credentials:

```
FLASK_ENV=development
FLASK_APP=app.py

SECRET_KEY=your-secret-key-change-in-production
JWT_SECRET_KEY=your-jwt-secret-key-change-in-production

DATABASE_URL=mysql+pymysql://root:password@localhost:3306/volunteer_db
```

Update `password` with your MySQL root password if needed.

### 6. Run the Application

```bash
python app.py
```

The application will:
- ✓ Create all database tables automatically
- ✓ Populate sample data
- ✓ Start on `http://localhost:5000`

## 🔐 Sample Credentials

### Organization Account
```
Email: organization@example.com
Password: Org@123
```

### Volunteer Accounts
```
Email: volunteer1@example.com
Password: Volunteer@123

Email: volunteer2@example.com
Password: Volunteer@123
```

## 🗺️ Project Structure

```
Volunteer2/
├── app.py                 # Main Flask application
├── models.py             # Database models (User, Event, Registration)
├── auth.py              # Authentication routes
├── event_routes.py      # Event management routes
├── config.py            # Configuration settings
├── utils.py             # Utility functions & decorators
├── requirements.txt     # Python dependencies
├── .env                 # Environment variables
│
├── templates/           # Jinja2 HTML templates
│   ├── base.html       # Base layout template
│   ├── index.html      # Home page
│   ├── about.html      # About page
│   ├── login.html      # Login form
│   ├── signup.html     # Sign up form
│   ├── events.html     # Events listing
│   ├── event_detail.html # Event details
│   ├── org_dashboard.html # Organization dashboard
│   ├── volunteer_dashboard.html # Volunteer dashboard
│   ├── create_event.html # Create event form
│   ├── edit_event.html # Edit event form
│   ├── my_registrations.html # Volunteer registrations
│   ├── 404.html        # 404 error page
│   └── 500.html        # 500 error page
│
└── static/              # Static files
    ├── css/
    │   └── style.css   # Main stylesheet
    └── js/
        └── main.js     # JavaScript utilities
```

## 🔑 Key Routes

### Authentication
- `GET /signup?type=volunteer` - Volunteer sign up
- `GET /signup?type=organization` - Organization sign up
- `POST /signup` - Process registration
- `GET /login` - Login form
- `POST /login` - Process login
- `GET /logout` - Logout

### Events (Public)
- `GET /events` - List all events
- `GET /event/<id>` - Event details

### Organization Routes
- `GET /org/dashboard` - Organization dashboard
- `GET /org/create-event` - Create event form
- `POST /org/create-event` - Save new event
- `GET /org/edit-event/<id>` - Edit event form
- `POST /org/edit-event/<id>` - Save event changes
- `POST /org/delete-event/<id>` - Delete event

### Volunteer Routes
- `GET /volunteer/dashboard` - Volunteer dashboard
- `GET /volunteer/my-registrations` - View registrations
- `POST /event/<id>/register` - Register for event
- `POST /event/<id>/unregister` - Unregister from event

## 🗄️ Database Schema

### Users Table
```sql
- id (Primary Key)
- email (Unique)
- password_hash
- name
- phone (Nullable)
- role (ENUM: 'organization', 'volunteer')
- organization_name (For organizations)
- description (For organizations)
- location (For organizations)
- created_at
```

### Events Table
```sql
- id (Primary Key)
- organization_id (Foreign Key)
- title
- description
- date
- start_time
- end_time
- location_text
- google_maps_link
- required_volunteers
- registered_volunteers
- status (ENUM: 'Open', 'Full')
- created_at
```

### Registrations Table
```sql
- id (Primary Key)
- event_id (Foreign Key)
- volunteer_id (Foreign Key)
- registered_at
- UNIQUE(event_id, volunteer_id)
```

## 🔒 Security Features

✅ **Password Security**
- Minimum 6 characters
- Must contain uppercase letter
- Must contain number
- Hashed with Werkzeug

✅ **Authentication**
- JWT tokens with short expiry (1 hour access, 30 days refresh)
- HTTP-only cookies prevent XSS attacks
- Role-based decorators for protected routes

✅ **Input Validation**
- Email format validation
- Phone number validation
- Required field validation
- Date/time validation

✅ **Data Protection**
- SQL injection prevention via SQLAlchemy ORM
- CSRF protection ready (can be enabled)
- Secure cookie settings

## 🎨 Customization

### Change Colors
Edit `/static/css/style.css` and modify the CSS variables:

```css
:root {
    --primary-color: #3498db;
    --secondary-color: #2c3e50;
    /* ... more colors ... */
}
```

### Modify Database
Update `/models.py` to add/modify tables:

```python
class Event(db.Model):
    # Add new columns here
    new_field = db.Column(db.String(255))
```

Then recreate the database.

## 📱 Responsive Design

The application is fully responsive:
- **Desktop**: Full navigation, multi-column layouts
- **Tablet**: Adjusted grid layouts
- **Mobile**: Single column, touch-friendly buttons

## 🚀 Production Deployment

Before deploying to production:

1. **Update .env**:
   ```
   FLASK_ENV=production
   SECRET_KEY=<generate-strong-random-key>
   JWT_SECRET_KEY=<generate-strong-random-key>
   ```

2. **Enable HTTPS**:
   ```python
   JWT_COOKIE_SECURE = True
   SESSION_COOKIE_SECURE = True
   ```

3. **Use production server** (e.g., Gunicorn):
   ```bash
   pip install gunicorn
   gunicorn app:app
   ```

4. **Set up reverse proxy** (nginx, Apache)

5. **Enable CSRF protection** in config.py:
   ```python
   JWT_COOKIE_CSRF_PROTECT = True
   ```

## 🐛 Troubleshooting

### Database Connection Error
- Ensure MySQL is running: `mysql -u root -p`
- Check DATABASE_URL in .env
- Verify MySQL user credentials

### Port Already in Use
- Change port in app.py: `app.run(port=5001)`

### Module Not Found
- Reinstall dependencies: `pip install -r requirements.txt`

### Login Not Working
- Clear cookies in browser
- Check .env SECRET_KEY and JWT_SECRET_KEY are set

### Events Not Showing
- Login as organization and create an event
- Or use sample data (run app.py once to initialize)

## 📝 Sample Usage

### As an Organization:

1. Sign up at `/signup?type=organization`
2. Login at `/login`
3. Go to dashboard (`/org/dashboard`)
4. Click "Create New Event"
5. Fill in event details
6. View registrations in dashboard

### As a Volunteer:

1. Sign up at `/signup?type=volunteer`
2. Login at `/login`
3. Browse events at `/events`
4. Click "View Details" on an event
5. Click "Register for This Event"
6. View your registrations at `/volunteer/my-registrations`

## 📚 Code Structure

### app.py
Main Flask application with:
- Blueprint registration
- Context processors
- Error handlers
- JWT handlers
- Database initialization

### models.py
Database models with:
- User (for both orgs and volunteers)
- Event
- Registration
- Relationships and constraints

### auth.py
Authentication routes:
- `/signup` - User registration
- `/login` - User login
- `/logout` - User logout
- `/refresh` - Token refresh

### event_routes.py
Event management:
- Event CRUD operations
- Registration management
- Role-based access control
- Business logic (conflicts, full events)

### utils.py
Utility functions:
- Decorators (@organization_required, @volunteer_required)
- Validation functions
- Database helpers
- Database initialization

### config.py
Configuration management:
- Environment variables
- Database settings
- JWT settings
- Different configs (dev, test, prod)

## 🤝 Contributing

This is a complete, standalone application. To extend it:

1. Add new models in `models.py`
2. Create new routes in appropriate blueprint file
3. Add templates in `templates/`
4. Add CSS in `static/css/style.css`
5. Add JavaScript in `static/js/main.js`

## 📄 License

This is a sample application for educational purposes.

## 📞 Support

For issues or questions:
1. Check the troubleshooting section
2. Review error messages in Flask console
3. Verify database connection
4. Check browser console for JavaScript errors

---

**Ready to run!** The application is production-ready and can be deployed as-is with proper environment configuration.
