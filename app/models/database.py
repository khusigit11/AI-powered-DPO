from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

# this is what connects our app to the sqlite database
db = SQLAlchemy()


class User(UserMixin, db.Model):
    """people who use the system - no admin/user split, everyone gets the same DPO tools"""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # when someone logs in for the first time we show them a welcome screen
    first_login = db.Column(db.Boolean, default=True)

    def set_password(self, password):
        """we never store the actual password - we scramble it into a hash instead"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """when someone tries to log in we check their password against the scrambled version"""
        return check_password_hash(self.password_hash, password)


class LoginAttempt(db.Model):
    """every time someone tries to log in we record it here - helps us spot brute-force attacks"""
    __tablename__ = 'login_attempts'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    success = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_agent = db.Column(db.String(500))


class Incident(db.Model):
    """when the detection engine catches something suspicious it gets saved here - this is task 5"""
    __tablename__ = 'incidents'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    # basic info about what was caught
    threat_type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    source_ip = db.Column(db.String(45))
    target_url = db.Column(db.String(500))
    payload = db.Column(db.Text)

    # the ai looks at the incident and tells us how bad it is
    severity = db.Column(db.String(20))
    severity_score = db.Column(db.Float)
    # if this is true it means we need to report it to the ICO within 72 hours
    is_reportable = db.Column(db.Boolean, default=False)

    # keeping track of what the dpo does about it
    status = db.Column(db.String(20), default='open')
    recommendation = db.Column(db.Text)

    # these are the fields required by gdpr article 33 for the breach report
    affected_data_categories = db.Column(db.Text)
    estimated_affected_count = db.Column(db.Integer)
    likely_consequences = db.Column(db.Text)
    remediation_measures = db.Column(db.Text)

    # did we already generate a pdf report for this?
    report_generated = db.Column(db.Boolean, default=False)
    report_generated_at = db.Column(db.DateTime)


class ActivityLog(db.Model):
    """records everything users do in the app - searches, url submissions, page visits etc"""
    __tablename__ = 'activity_logs'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    ip_address = db.Column(db.String(45))
    action = db.Column(db.String(100), nullable=False)
    url = db.Column(db.String(500))
    method = db.Column(db.String(10))
    input_data = db.Column(db.Text)
    # if the detection engine flagged this activity as suspicious
    flagged = db.Column(db.Boolean, default=False)


class ChecklistProgress(db.Model):
    """the heart of the system - tracks which of the 7 dpo tasks the user has finished"""
    __tablename__ = 'checklist_progress'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    # which task (1 through 7)
    task_number = db.Column(db.Integer, nullable=False)
    task_name = db.Column(db.String(100), nullable=False)
    # has the user actually completed this task?
    completed = db.Column(db.Boolean, default=False)
    completed_at = db.Column(db.DateTime)
    # whatever the ai produced when helping with this task
    ai_response = db.Column(db.Text)


class ROPARecord(db.Model):
    """task 1 - knowing what personal data your organisation actually holds and why"""
    __tablename__ = 'ropa_records'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # the basics - what data, why, and is it legal to collect
    data_categories = db.Column(db.Text, nullable=False)
    purpose = db.Column(db.Text, nullable=False)
    lawful_basis = db.Column(db.Text, nullable=False)
    # who gets to see this data
    data_recipients = db.Column(db.Text)
    # how long before we delete it
    retention_period = db.Column(db.Text)
    # what we do to keep it safe
    security_measures = db.Column(db.Text)
    # the full ropa document that the ai puts together
    ai_generated_report = db.Column(db.Text)


class ComplianceRecord(db.Model):
    """task 2 - checking if the organisation is actually following gdpr rules"""
    __tablename__ = 'compliance_records'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # answers to each compliance question - yes means doing it, partial means sort of, no means not doing it
    data_minimisation = db.Column(db.String(20))
    lawful_basis_documented = db.Column(db.String(20))
    consent_obtained = db.Column(db.String(20))
    data_accurate = db.Column(db.String(20))
    retention_followed = db.Column(db.String(20))
    security_measures = db.Column(db.String(20))
    breach_process_exists = db.Column(db.String(20))
    dpo_appointed = db.Column(db.String(20))

    # the ai gives a score out of 100 and tells you what to fix
    compliance_score = db.Column(db.Integer)
    ai_assessment = db.Column(db.Text)
    recommendations = db.Column(db.Text)


class DPIARecord(db.Model):
    """task 3 - before you start doing something new with peoples data you need to check the risks"""
    __tablename__ = 'dpia_records'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # what are you planning to do
    project_name = db.Column(db.String(200), nullable=False)
    project_description = db.Column(db.Text, nullable=False)
    # what personal data will be involved
    data_involved = db.Column(db.Text, nullable=False)
    # whose data is it
    individuals_affected = db.Column(db.Text)
    # the ai figures out how risky this is
    risk_level = db.Column(db.String(20))
    ai_assessment = db.Column(db.Text)
    # what should you do to reduce the risk
    recommendations = db.Column(db.Text)


class SARRequest(db.Model):
    """task 4 - when someone asks what data you have about them you must respond within 30 days"""
    __tablename__ = 'sar_requests'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # who is asking
    requester_name = db.Column(db.String(200), nullable=False)
    requester_email = db.Column(db.String(200))
    # what do they want - could be access, correction, deletion, or a copy of their data
    request_type = db.Column(db.String(50), nullable=False)
    request_details = db.Column(db.Text, nullable=False)
    # you have exactly 30 days to respond - this tracks that deadline
    deadline = db.Column(db.DateTime, nullable=False)
    # where are we with this request
    status = db.Column(db.String(20), default='pending')
    # the ai drafts a proper response letter
    ai_response = db.Column(db.Text)
    completed_at = db.Column(db.DateTime)


class Policy(db.Model):
    """task 6 - every org needs written rules about how they handle personal data"""
    __tablename__ = 'policies'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # the actual policy
    policy_name = db.Column(db.String(200), nullable=False)
    policy_content = db.Column(db.Text, nullable=False)
    # policies need regular reviews to stay up to date
    last_reviewed = db.Column(db.DateTime)
    next_review_due = db.Column(db.DateTime)
    # the ai reads the policy and tells you whats missing or outdated
    ai_review = db.Column(db.Text)
    ai_suggestions = db.Column(db.Text)


class TrainingRecord(db.Model):
    """task 7 - staff need to know the basics of data protection or they will make mistakes"""
    __tablename__ = 'training_records'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # what the training covers
    topic = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text)
    # how they did on the quiz at the end
    quiz_score = db.Column(db.Integer)
    quiz_total = db.Column(db.Integer)
    # did they get enough right to pass
    passed = db.Column(db.Boolean, default=False)
    completed_at = db.Column(db.DateTime)