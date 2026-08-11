from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime
from app.models.database import db, User, LoginAttempt, Incident, ActivityLog

# Blueprints group routes together - main for regular users, admin for DPO dashboard
main_bp = Blueprint('main', __name__)
admin_bp = Blueprint('admin', __name__)


#  this is public routes for homepage, login, egister

@main_bp.route('/')
def index():
    """Homepage - first thing users see"""
    return render_template('index.html')


@main_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Login page - all attempts are logged for brute-force detection"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        ip_address = request.remote_addr

        # Record this login attempt in the database
        login_attempt = LoginAttempt(
            username=username,
            ip_address=ip_address,
            success=False,
            user_agent=request.headers.get('User-Agent', '')
        )

        # Try to find the user and check password
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            # Successful login
            login_attempt.success = True
            db.session.add(login_attempt)
            db.session.commit()

            login_user(user)
            flash(f'Welcome back, {user.username}!', 'success')

            if user.role == 'admin':
                return redirect(url_for('admin.dashboard'))
            return redirect(url_for('main.dashboard'))
        else:
            # Failed login - save to database
            db.session.add(login_attempt)
            db.session.commit()
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')


@main_bp.route('/register', methods=['GET', 'POST'])
def register():
    """Registration page for new users"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '')
        email = request.form.get('email', '')
        password = request.form.get('password', '')

        # Check if username or email already taken
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return render_template('register.html')

        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return render_template('register.html')

        # Create the new user with hashed password
        new_user = User(username=username, email=email, role='user')
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('main.login'))

    return render_template('register.html')


@main_bp.route('/logout')
@login_required
def logout():
    """Log the user out and redirect to homepage"""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.index'))


#  User routes - Pages for logged in users

@main_bp.route('/dashboard')
@login_required
def dashboard():
    """User dashboard - shown after login"""
    return render_template('user_dashboard.html')


@main_bp.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    """Search page - used to test injection detection later"""
    results = []
    if request.method == 'POST':
        query = request.form.get('query', '')

        # Log this activity
        activity = ActivityLog(
            user_id=current_user.id,
            ip_address=request.remote_addr,
            action='search',
            url=request.url,
            method='POST',
            input_data=query
        )
        db.session.add(activity)
        db.session.commit()

        results = [f'Search result for: {query}']
        flash('Search completed.', 'success')

    return render_template('search.html', results=results)


@main_bp.route('/submit-url', methods=['GET', 'POST'])
@login_required
def submit_url():
    """URL submission page - used to test phishing detection later"""
    if request.method == 'POST':
        url_input = request.form.get('url', '')

        # Log this activity
        activity = ActivityLog(
            user_id=current_user.id,
            ip_address=request.remote_addr,
            action='url_submission',
            url=request.url,
            method='POST',
            input_data=url_input
        )
        db.session.add(activity)
        db.session.commit()

        flash('URL submitted successfully.', 'success')

    return render_template('submit_url.html')

#  ADMIN ROUTES - DPO Dashboard

@admin_bp.route('/dashboard')
@login_required
def dashboard():
    """DPO compliance dashboard - only accessible by admin"""
    if current_user.role != 'admin':
        flash('Access denied. Admin only.', 'danger')
        return redirect(url_for('main.dashboard'))

    # Gather stats for the dashboard
    total_incidents = Incident.query.count()
    open_incidents = Incident.query.filter_by(status='open').count()
    critical_incidents = Incident.query.filter_by(severity='Critical').count()
    reportable_incidents = Incident.query.filter_by(is_reportable=True).count()
    total_users = User.query.count()

    # Get recent incidents
    recent_incidents = Incident.query.order_by(Incident.timestamp.desc()).limit(20).all()

    # Get recent login attempts
    recent_logins = LoginAttempt.query.order_by(LoginAttempt.timestamp.desc()).limit(10).all()

    stats = {
        'total_incidents': total_incidents,
        'open_incidents': open_incidents,
        'critical_incidents': critical_incidents,
        'reportable_incidents': reportable_incidents,
        'total_users': total_users,
    }

    return render_template('admin/dashboard.html',
                         stats=stats,
                         recent_incidents=recent_incidents,
                         recent_logins=recent_logins)


@admin_bp.route('/incidents')
@login_required
def incidents():
    """List all security incidents"""
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('main.dashboard'))

    incidents = Incident.query.order_by(Incident.timestamp.desc()).all()
    return render_template('admin/incidents.html', incidents=incidents)


@admin_bp.route('/incident/<int:incident_id>')
@login_required
def incident_detail(incident_id):
    """View full details of a single incident"""
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('main.dashboard'))

    incident = Incident.query.get_or_404(incident_id)
    return render_template('admin/incident_detail.html', incident=incident)


@admin_bp.route('/login-attempts')
@login_required
def login_attempts():
    """Monitor all login attempts"""
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('main.dashboard'))

    attempts = LoginAttempt.query.order_by(LoginAttempt.timestamp.desc()).all()
    return render_template('admin/login_attempts.html', attempts=attempts)


@admin_bp.route('/activity-log')
@login_required
def activity_log():
    """View all user activity in the application"""
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('main.dashboard'))

    activities = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(100).all()
    return render_template('admin/activity_log.html', activities=activities)