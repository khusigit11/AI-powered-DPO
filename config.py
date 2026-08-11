import os

class Config:
    """
    Configuration settings for the AI-Powered Data Protection Officer system.
    This file stores all the settings the app needs to run - things like
    database location, security keys, and detection thresholds.
    """
    # This is a secret key used by Flask to keep user sessions secure.
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'ai-dpo-secret-key-2026'
    
    # This tells the app where to store the database file.
    # We are using SQLite, which stores everything in a single file called ai_dpo.db
    SQLALCHEMY_DATABASE_URI = 'sqlite:///ai_dpo.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Brute force detection settings
    # If someone fails to log in 5 times within 5 minutes from the same IP address,
    # the system flags it as a possible brute-force attack.
    MAX_FAILED_LOGINS = 5
    LOGIN_WINDOW_SECONDS = 300  # 5 minutes
    
    # Report output folder
    # This is the folder where GDPR breach reports (PDFs) will be saved.
      # os.path just figures out the correct folder path on any computer.
    REPORT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reports')