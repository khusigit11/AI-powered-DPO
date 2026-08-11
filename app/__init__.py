from flask import Flask
from flask_login import LoginManager
from config import Config
from app.models.database import db

# This handles user login sessions
login_manager = LoginManager()
login_manager.login_view = 'main.login'

def create_app():
    """
    App factory - creates and configures the Flask application.
    This is the starting point of the entire system.
    """
    app = Flask(__name__)
    app.config.from_object(Config)

    # Connect database and login manager to the app
    db.init_app(app)
    login_manager.init_app(app)

    # Tell Flask-Login how to find a user by their ID
    from app.models.database import User

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Register route blueprints (we'll create these next)
    from app.routes import main_bp, admin_bp
    app.register_blueprint(main_bp)
    app.register_blueprint(admin_bp, url_prefix='/admin')

    # Create all database tables when the app starts
    with app.app_context():
        db.create_all()

        # Create default admin account if none exists
        admin = User.query.filter_by(role='admin').first()
        if not admin:
            admin = User(username='admin', email='admin@aidpo.local', role='admin')
            admin.set_password('admin123')
            db.session.add(admin)

            # Also create a test user
            test_user = User(username='testuser', email='user@aidpo.local', role='user')
            test_user.set_password('user123')
            db.session.add(test_user)

            db.session.commit()
            print('[AI-DPO] Default admin and test user created.')

    return app