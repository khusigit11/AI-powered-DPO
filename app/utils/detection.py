import re
from datetime import datetime, timedelta
from app.models.database import db, LoginAttempt, Incident, ActivityLog


class DetectionEngine:
    """
    The is the core detection engine for the AI-DPO system.
    scans all user inputs for five types of web application threats:
    1. Brute-force login attempts (too many failed logins)
    2. SQL injection (trying to hack db)
    3. Cross-site scripting (XSS) (trying to run malicious scripts)
    4. Phishing URLs (fake/sus link)
    5. Path traversal (trying to access server files)
    
    This mirrors the monitoring function of a real DPO (Article 39).
    """

    # Sqlnjection patterns
    # These catch common SQL attack strings like ' OR 1=1 -- into login forms to trick db into giving access
    SQL_PATTERNS = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|EXEC)\b)",
        r"(--|;|/\*|\*/)",
        r"(\bOR\b\s+\d+\s*=\s*\d+)",
        r"('|\")(\s)*(OR|AND)(\s)*('|\")",
        r"(\bOR\b\s+'[^']*'\s*=\s*'[^']*')",
    ]

    # XSSpatterns
    # These catch script tags and event handlers used in XSS attacks. into webpages to steal cookie or redirect usjer
    XSS_PATTERNS = [
        r"<\s*script[^>]*>",
        r"javascript\s*:",
        r"on(error|load|click|mouseover|focus|blur)\s*=",
        r"<\s*img[^>]+onerror",
        r"<\s*iframe",
        r"eval\s*\(",
        r"document\.(cookie|location|write)",
    ]

    # Phishing URL patterns
    # These catch suspicious URLs like IP-based links or fake login pages
    PHISHING_PATTERNS = [
        r"(login|signin|account|secure|verify).*\.(tk|ml|ga|cf|gq)",
        r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        r"bit\.ly/|tinyurl\.com/|goo\.gl/|t\.co/",
        r"\.(exe|bat|cmd|scr|pif)$",
    ]

    # Path traversal patterns
    # These catch attempts to access system files like /etc/passwd
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.\\",
        r"/etc/(passwd|shadow|hosts)",
        r"(c:|C:)\\(windows|winnt)",
        r"%2e%2e(%2f|/)",
    ]

    def __init__(self, app=None):
        """Set up detection thresholds from app config"""
        self.max_failed_logins = 5
        self.login_window = 300

        if app:
            self.max_failed_logins = app.config.get('MAX_FAILED_LOGINS', 5)
            self.login_window = app.config.get('LOGIN_WINDOW_SECONDS', 300)

    def check_brute_force(self, username, ip_address):
        """ Check if too many failed logins happened recently.
        If someone fails 5 times in 5 minutes = brute-force alert """

        window_start = datetime.utcnow() - timedelta(seconds=self.login_window)

        failed_count = LoginAttempt.query.filter(
            LoginAttempt.username == username,
            LoginAttempt.ip_address == ip_address,
            LoginAttempt.success == False,
            LoginAttempt.timestamp >= window_start
        ).count()

        if failed_count >= self.max_failed_logins:
            return {
                'detected': True,
                'threat_type': 'brute_force',
                'description': f'{failed_count} failed login attempts for "{username}" from {ip_address} in {self.login_window // 60} minutes.',
                'payload': f'Username: {username}, Failed attempts: {failed_count}',
                'source_ip': ip_address
            }

        return {'detected': False}

    def check_sql_injection(self, input_text):
        """Scan input for SQL injection patterns like ' OR 1=1 """
        if not input_text:
            return {'detected': False}

        for pattern in self.SQL_PATTERNS:
            match = re.search(pattern, input_text, re.IGNORECASE)
            if match:
                return {
                    'detected': True,
                    'threat_type': 'sql_injection',
                    'description': f'SQL injection detected. Matched: "{match.group()}"',
                    'payload': input_text[:500]
                }

        return {'detected': False}

    def check_xss(self, input_text):
        """Scan input for XSS patterns like <script>alert('xss')</script>"""
        if not input_text:
            return {'detected': False}

        for pattern in self.XSS_PATTERNS:
            match = re.search(pattern, input_text, re.IGNORECASE)
            if match:
                return {
                    'detected': True,
                    'threat_type': 'xss',
                    'description': f'XSS attack detected. Matched: "{match.group()}"',
                    'payload': input_text[:500]
                }

        return {'detected': False}

    def check_phishing_url(self, url):
        """Check if a URL matches known phishing patterns"""
        if not url:
            return {'detected': False}

        for pattern in self.PHISHING_PATTERNS:
            match = re.search(pattern, url, re.IGNORECASE)
            if match:
                return {
                    'detected': True,
                    'threat_type': 'phishing_url',
                    'description': f'Phishing URL detected. Matched: "{match.group()}"',
                    'payload': url[:500]
                }

        return {'detected': False}

    def check_path_traversal(self, input_text):
        """Check for path traversal like ../../etc/passwd"""
        if not input_text:
            return {'detected': False}

        for pattern in self.PATH_TRAVERSAL_PATTERNS:
            match = re.search(pattern, input_text, re.IGNORECASE)
            if match:
                return {
                    'detected': True,
                    'threat_type': 'path_traversal',
                    'description': f'Path traversal detected. Matched: "{match.group()}"',
                    'payload': input_text[:500]
                }

        return {'detected': False}

    def scan_all(self, input_text, source_ip=None, target_url=None):
        """ Run ALL detection checks on one input.
        Returns a list of every threat found """
        
        threats = []

        checks = [
            self.check_sql_injection(input_text),
            self.check_xss(input_text),
            self.check_phishing_url(input_text),
            self.check_path_traversal(input_text),
        ]

        for result in checks:
            if result['detected']:
                result['source_ip'] = source_ip
                result['target_url'] = target_url
                threats.append(result)

        return threats

    def create_incident(self, detection_result, source_ip=None, target_url=None):
        """Save a detected threat as an incident in the database"""
        incident = Incident(
            threat_type=detection_result['threat_type'],
            description=detection_result['description'],
            source_ip=source_ip or detection_result.get('source_ip', 'unknown'),
            target_url=target_url,
            payload=detection_result.get('payload', ''),
            status='open'
        )

        db.session.add(incident)
        db.session.commit()

        return incident