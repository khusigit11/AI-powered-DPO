from flask import Flask
from flask_login import LoginManager
from config import Config
from app.models.database import db

# handles user login sessions
login_manager = LoginManager()
login_manager.login_view = 'main.login'

def create_app():
    """sets up the whole flask application - this runs when we start the app"""
    app = Flask(__name__)
    app.config.from_object(Config)

    # connect database and login manager to the ap
    db.init_app(app)
    login_manager.init_app(app)

    # tells flask how to find a user when they come back
    from app.models.database import User

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # registe r the routes
    from app.routes import main_bp
    app.register_blueprint(main_bp)

    # creates all database tables when the app first starts
    with app.app_context():
        db.create_all()

        # set up the 7 dpo checklist tasks for any new user
        # this happens automatically when they first register

    return app