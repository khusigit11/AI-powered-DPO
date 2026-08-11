from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

# This creates the database connection that all our tables will use
db = SQLAlchemy()


class User(UserMixin, db.Model):
    """Stores user accounts - both regular users and admin (DPO)"""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='user')  # 'user' or 'admin'
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        """Hash the password so we never store it in plain text"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Check if the entered password matches the stored hash"""
        return check_password_hash(self.password_hash, password)


class LoginAttempt(db.Model):
    """Tracks every login attempt - used for brute-force detection"""
    __tablename__ = 'login_attempts'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    success = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_agent = db.Column(db.String(500))


class Incident(db.Model):
    """Security incidents detected by the system - core DPO audit trail"""
    __tablename__ = 'incidents'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    # What happened
    threat_type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    source_ip = db.Column(db.String(45))
    target_url = db.Column(db.String(500))
    payload = db.Column(db.Text)  # the suspicious input that triggered detection

    # AI classification results
    severity = db.Column(db.String(20))    # Low, Medium, High, Critical
    severity_score = db.Column(db.Float)   # 0.0 to 1.0 confidence from ML model
    is_reportable = db.Column(db.Boolean, default=False)  # meets Article 33 threshold?

    # DPO response tracking
    status = db.Column(db.String(20), default='open')
    recommendation = db.Column(db.Text)  # AI-generated DPO advice

    # Article 33 report fields
    affected_data_categories = db.Column(db.Text)
    estimated_affected_count = db.Column(db.Integer)
    likely_consequences = db.Column(db.Text)
    remediation_measures = db.Column(db.Text)

    # Report tracking
    report_generated = db.Column(db.Boolean, default=False)
    report_generated_at = db.Column(db.DateTime)


class ActivityLog(db.Model):
    """Logs all user activity in the web app for monitoring"""
    __tablename__ = 'activity_logs'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    ip_address = db.Column(db.String(45))
    action = db.Column(db.String(100), nullable=False)
    url = db.Column(db.String(500))
    method = db.Column(db.String(10))  # GET or POST
    input_data = db.Column(db.Text)
    flagged = db.Column(db.Boolean, default=False)


class ComplianceCheck(db.Model):
    """Regular compliance checks - mirrors DPO audit function"""
    __tablename__ = 'compliance_checks'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    check_type = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), nullable=False)  # pass, warning, fail
    details = db.Column(db.Text)
    recommendation = db.Column(db.Text)