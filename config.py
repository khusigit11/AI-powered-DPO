import os
from dotenv import load_dotenv

# load the api key from .env file so we dont have to set it every time
load_dotenv()

class Config:
    # secret key for encrypting user sessions
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'ai-dpo-secret-key-2026'

    # sqlite database
    SQLALCHEMY_DATABASE_URI = 'sqlite:///ai_dpo.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # brute force detection settings
    MAX_FAILED_LOGINS = 5
    LOGIN_WINDOW_SECONDS = 300

    # folder for pdf reports
    REPORT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reports')

    # claude api key loaded from .env file
    ANTHROPIC_API_KEY = os.environ.get('ANTHROPIC_API_KEY') or ''