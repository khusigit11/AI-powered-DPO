import os

class Config:
    # secret key for encrypting user sessions
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'ai-dpo-secret-key-2026'

    # sqlite database - stores everything in one file
    SQLALCHEMY_DATABASE_URI = 'sqlite:///ai_dpo.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # brute force detection: 5 failed logins within 5 minutes triggers alert
    MAX_FAILED_LOGINS = 5
    LOGIN_WINDOW_SECONDS = 300

    # folder where gdpr breach report pdfs will be saved
    REPORT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reports')

    # claude api key - loaded from environment variable so it stays private
    ANTHROPIC_API_KEY = os.environ.get('ANTHROPIC_API_KEY') or ''