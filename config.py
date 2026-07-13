import os
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


def env_bool(name, default=False):
    value = os.environ.get(name)

    if value is None:
        return default

    return value.strip().lower() in {
        "1", "true", "yes", "on"
    }


def get_database_url():
    database_url = os.environ.get("DATABASE_URL")

    if not database_url:
        return "sqlite:///" + os.path.join(
            BASE_DIR,
            "database.db"
        )

    # SQLAlchemy compatibility for old Heroku-style URLs.
    if database_url.startswith("postgres://"):
        database_url = database_url.replace(
            "postgres://",
            "postgresql://",
            1
        )

    return database_url


class Config:
    # =========================
    # Flask
    # =========================
    SECRET_KEY = os.environ.get(
        "SECRET_KEY",
        "dev-only-change-this-secret-key"
    )

    DEBUG = env_bool("DEBUG", False)
    TESTING = env_bool("TESTING", False)

    # =========================
    # Database
    # =========================
    SQLALCHEMY_DATABASE_URI = get_database_url()
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": 300,
    }

    # =========================
    # Session / Cookies
    # =========================
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = env_bool(
        "SESSION_COOKIE_SECURE",
        bool(os.environ.get("VERCEL"))
    )
    SESSION_COOKIE_SAMESITE = "Lax"

    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SECURE = SESSION_COOKIE_SECURE
    REMEMBER_COOKIE_SAMESITE = "Lax"
    REMEMBER_COOKIE_DURATION = timedelta(days=30)

    # =========================
    # Uploads
    # =========================
    UPLOAD_FOLDER = os.environ.get(
        "UPLOAD_FOLDER",
        os.path.join(BASE_DIR, "uploads")
    )

    MAX_CONTENT_LENGTH = 16 * 1024 * 1024

    ALLOWED_EXTENSIONS = {
        "pdf",
        "png",
        "jpg",
        "jpeg",
        "doc",
        "docx",
        "txt",
        "csv",
    }

    # =========================
    # Reports / Exports
    # =========================
    EXPORT_FOLDER = os.environ.get(
        "EXPORT_FOLDER",
        os.path.join(BASE_DIR, "exports")
    )

    REPORT_FOLDER = os.environ.get(
        "REPORT_FOLDER",
        os.path.join(BASE_DIR, "reports")
    )

    # =========================
    # Password Policy
    # =========================
    MIN_PASSWORD_LENGTH = int(
        os.environ.get("MIN_PASSWORD_LENGTH", "8")
    )

    REQUIRE_UPPERCASE = True
    REQUIRE_LOWERCASE = True
    REQUIRE_NUMBER = True
    REQUIRE_SPECIAL = True

    # =========================
    # Email / OTP
    # =========================
    MAIL_SERVER = os.environ.get(
        "MAIL_SERVER",
        "smtp.gmail.com"
    )

    MAIL_PORT = int(
        os.environ.get("MAIL_PORT", "587")
    )

    MAIL_USE_TLS = env_bool("MAIL_USE_TLS", True)
    MAIL_USE_SSL = env_bool("MAIL_USE_SSL", False)

    MAIL_USERNAME = os.environ.get("MAIL_USERNAME")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD")

    MAIL_DEFAULT_SENDER = os.environ.get(
        "MAIL_DEFAULT_SENDER"
    ) or MAIL_USERNAME

    MAIL_SUPPRESS_SEND = env_bool(
        "MAIL_SUPPRESS_SEND",
        False
    )

    OTP_EXPIRY_MINUTES = int(
        os.environ.get("OTP_EXPIRY_MINUTES", "10")
    )

    # =========================
    # Anthropic AI
    # =========================
    ANTHROPIC_API_KEY = os.environ.get(
        "ANTHROPIC_API_KEY"
    )

    ANTHROPIC_MODEL = os.environ.get(
        "ANTHROPIC_MODEL",
        "claude-opus-4-1"
    )

    # =========================
    # Gemini AI
    # =========================
    GEMINI_API_KEY = os.environ.get(
        "GEMINI_API_KEY"
    )

    GEMINI_MODEL = os.environ.get(
        "GEMINI_MODEL",
        "gemini-2.5-pro"
    )

    # =========================
    # VirusTotal
    # =========================
    VIRUSTOTAL_API_KEY = os.environ.get(
        "VIRUSTOTAL_API_KEY"
    )

    # =========================
    # AbuseIPDB
    # =========================
    ABUSEIPDB_API_KEY = os.environ.get(
        "ABUSEIPDB_API_KEY"
    )

    # =========================
    # Google Safe Browsing
    # =========================
    GOOGLE_SAFE_BROWSING_KEY = os.environ.get(
        "GOOGLE_SAFE_BROWSING_KEY"
    )

    # =========================
    # Rate Limiting
    # =========================
    RATELIMIT_DEFAULT = os.environ.get(
        "RATELIMIT_DEFAULT",
        "100/hour"
    )

    LOGIN_LIMIT = os.environ.get(
        "LOGIN_LIMIT",
        "10/minute"
    )

    REGISTER_LIMIT = os.environ.get(
        "REGISTER_LIMIT",
        "5/hour"
    )

    # =========================
    # Logging
    # =========================
    LOG_FOLDER = os.environ.get(
        "LOG_FOLDER",
        os.path.join(BASE_DIR, "logs")
    )

    LOG_LEVEL = os.environ.get(
        "LOG_LEVEL",
        "INFO"
    )

    # =========================
    # PWA
    # =========================
    APP_NAME = os.environ.get(
        "APP_NAME",
        "AI Phishing Detector"
    )

    APP_SHORT_NAME = os.environ.get(
        "APP_SHORT_NAME",
        "PhishAI"
    )

    THEME_COLOR = os.environ.get(
        "THEME_COLOR",
        "#2563eb"
    )

    BACKGROUND_COLOR = os.environ.get(
        "BACKGROUND_COLOR",
        "#0f172a"
    )

    # =========================
    # Dashboard
    # =========================
    ITEMS_PER_PAGE = int(
        os.environ.get("ITEMS_PER_PAGE", "10")
    )

    MAX_HISTORY = int(
        os.environ.get("MAX_HISTORY", "1000")
    )

    # =========================
    # Admin
    # =========================
    ADMIN_EMAIL = os.environ.get(
        "ADMIN_EMAIL",
        "admin@example.com"
    )

    # Never hard-code the real admin password.
    ADMIN_PASSWORD = os.environ.get(
        "ADMIN_PASSWORD"
    )

    # =========================
    # Security / CSRF
    # =========================
    CSRF_ENABLED = True
    WTF_CSRF_ENABLED = True

    WTF_CSRF_TIME_LIMIT = int(
        os.environ.get("WTF_CSRF_TIME_LIMIT", "3600")
    )

    SECURITY_PASSWORD_SALT = os.environ.get(
        "SECURITY_PASSWORD_SALT",
        "dev-only-change-this-salt"
    )

    # =========================
    # PDF
    # =========================
    PDF_AUTHOR = os.environ.get(
        "PDF_AUTHOR",
        "Jal Modi"
    )

    PDF_TITLE = os.environ.get(
        "PDF_TITLE",
        "AI Phishing Email Report"
    )

    PDF_SUBJECT = os.environ.get(
        "PDF_SUBJECT",
        "Cyber Security"
    )

    # =========================
    # CSV / Excel
    # =========================
    CSV_FILENAME = os.environ.get(
        "CSV_FILENAME",
        "Scan_Report.csv"
    )

    EXCEL_FILENAME = os.environ.get(
        "EXCEL_FILENAME",
        "Scan_Report.xlsx"
    )

    # =========================
    # Application
    # =========================
    COMPANY_NAME = os.environ.get(
        "COMPANY_NAME",
        "Hexa Shield"
    )

    VERSION = os.environ.get(
        "APP_VERSION",
        "2.0"
    )

    COPYRIGHT = os.environ.get(
        "COPYRIGHT",
        "© 2026 Jal Modi"
    )

    SUPPORT_EMAIL = os.environ.get(
        "SUPPORT_EMAIL",
        "support@example.com"
    )
