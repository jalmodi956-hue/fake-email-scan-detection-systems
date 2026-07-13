import os
from datetime import timedelta


BASE_DIR = os.path.abspath(
    os.path.dirname(__file__)
)


# ==========================
# ENV BOOLEAN
# ==========================

def env_bool(name, default=False):

    value = os.environ.get(name)

    if value is None:
        return default

    return value.strip().lower() in {
        "1",
        "true",
        "yes",
        "on"
    }


# ==========================
# DATABASE URL
# ==========================

def get_database_url():

    database_url = (
        os.environ.get("DATABASE_URL")
        or os.environ.get(
            "FAKEEMAILDB_URL_DATABASE_URL"
        )
    )

    if not database_url:

        return "sqlite:///" + os.path.join(
            BASE_DIR,
            "database.db"
        )

    if database_url.startswith(
        "postgres://"
    ):

        database_url = database_url.replace(
            "postgres://",
            "postgresql://",
            1
        )

    return database_url


# ==========================
# CONFIG
# ==========================

class Config:

    # ==========================
    # FLASK
    # ==========================

    SECRET_KEY = os.environ.get(
        "SECRET_KEY",
        "dev-only-change-this-secret-key"
    )

    DEBUG = env_bool(
        "DEBUG",
        False
    )

    TESTING = env_bool(
        "TESTING",
        False
    )


    # ==========================
    # DATABASE
    # ==========================

    SQLALCHEMY_DATABASE_URI = (
        get_database_url()
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": 300
    }


    # ==========================
    # SESSION / COOKIES
    # ==========================

    PERMANENT_SESSION_LIFETIME = (
        timedelta(days=7)
    )

    SESSION_COOKIE_HTTPONLY = True

    SESSION_COOKIE_SECURE = env_bool(
        "SESSION_COOKIE_SECURE",
        bool(os.environ.get("VERCEL"))
    )

    SESSION_COOKIE_SAMESITE = "Lax"

    REMEMBER_COOKIE_HTTPONLY = True

    REMEMBER_COOKIE_SECURE = (
        SESSION_COOKIE_SECURE
    )

    REMEMBER_COOKIE_SAMESITE = "Lax"

    REMEMBER_COOKIE_DURATION = (
        timedelta(days=30)
    )


    # ==========================
    # UPLOADS
    # ==========================

    UPLOAD_FOLDER = os.environ.get(
        "UPLOAD_FOLDER",
        (
            "/tmp/uploads"
            if os.environ.get("VERCEL")
            else os.path.join(
                BASE_DIR,
                "uploads"
            )
        )
    )

    MAX_CONTENT_LENGTH = (
        16 * 1024 * 1024
    )

    ALLOWED_EXTENSIONS = {
        "pdf",
        "png",
        "jpg",
        "jpeg",
        "doc",
        "docx",
        "txt",
        "csv"
    }


    # ==========================
    # EXPORTS
    # ==========================

    EXPORT_FOLDER = os.environ.get(
        "EXPORT_FOLDER",
        (
            "/tmp/exports"
            if os.environ.get("VERCEL")
            else os.path.join(
                BASE_DIR,
                "exports"
            )
        )
    )

    REPORT_FOLDER = os.environ.get(
        "REPORT_FOLDER",
        (
            "/tmp/reports"
            if os.environ.get("VERCEL")
            else os.path.join(
                BASE_DIR,
                "reports"
            )
        )
    )


    # ==========================
    # PASSWORD POLICY
    # ==========================

    MIN_PASSWORD_LENGTH = int(
        os.environ.get(
            "MIN_PASSWORD_LENGTH",
            "8"
        )
    )

    REQUIRE_UPPERCASE = True

    REQUIRE_LOWERCASE = True

    REQUIRE_NUMBER = True

    REQUIRE_SPECIAL = True


    # ==========================
    # EMAIL
    # ==========================

    MAIL_SERVER = os.environ.get(
        "MAIL_SERVER",
        "smtp.gmail.com"
    )

    MAIL_PORT = int(
        os.environ.get(
            "MAIL_PORT",
            "587"
        )
    )

    MAIL_USE_TLS = env_bool(
        "MAIL_USE_TLS",
        True
    )

    MAIL_USE_SSL = env_bool(
        "MAIL_USE_SSL",
        False
    )

    MAIL_USERNAME = os.environ.get(
        "MAIL_USERNAME"
    )

    MAIL_PASSWORD = os.environ.get(
        "MAIL_PASSWORD"
    )

    MAIL_DEFAULT_SENDER = (
        os.environ.get(
            "MAIL_DEFAULT_SENDER"
        )
        or MAIL_USERNAME
    )

    MAIL_SUPPRESS_SEND = env_bool(
        "MAIL_SUPPRESS_SEND",
        False
    )


    # ==========================
    # ANTHROPIC AI
    # ==========================

    ANTHROPIC_API_KEY = os.environ.get(
        "ANTHROPIC_API_KEY"
    )

    ANTHROPIC_MODEL = os.environ.get(
        "ANTHROPIC_MODEL",
        "claude-opus-4-1"
    )


    # ==========================
    # GEMINI AI
    # ==========================

    GEMINI_API_KEY = os.environ.get(
        "GEMINI_API_KEY"
    )

    GEMINI_MODEL = os.environ.get(
        "GEMINI_MODEL",
        "gemini-2.5-pro"
    )


    # ==========================
    # VIRUSTOTAL
    # ==========================

    VIRUSTOTAL_API_KEY = os.environ.get(
        "VIRUSTOTAL_API_KEY"
    )


    # ==========================
    # ABUSEIPDB
    # ==========================

    ABUSEIPDB_API_KEY = os.environ.get(
        "ABUSEIPDB_API_KEY"
    )


    # ==========================
    # GOOGLE SAFE BROWSING
    # ==========================

    GOOGLE_SAFE_BROWSING_KEY = (
        os.environ.get(
            "GOOGLE_SAFE_BROWSING_KEY"
        )
    )


    # ==========================
    # RATE LIMITING
    # ==========================

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


    # ==========================
    # LOGGING
    # ==========================

    LOG_FOLDER = os.environ.get(
        "LOG_FOLDER",
        (
            "/tmp/logs"
            if os.environ.get("VERCEL")
            else os.path.join(
                BASE_DIR,
                "logs"
            )
        )
    )

    LOG_LEVEL = os.environ.get(
        "LOG_LEVEL",
        "INFO"
    )


    # ==========================
    # PWA
    # ==========================

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


    # ==========================
    # DASHBOARD
    # ==========================

    ITEMS_PER_PAGE = int(
        os.environ.get(
            "ITEMS_PER_PAGE",
            "10"
        )
    )

    MAX_HISTORY = int(
        os.environ.get(
            "MAX_HISTORY",
            "1000"
        )
    )


    # ==========================
    # ADMIN
    # ==========================

    ADMIN_EMAIL = os.environ.get(
        "ADMIN_EMAIL",
        "admin@example.com"
    )

    ADMIN_PASSWORD = os.environ.get(
        "ADMIN_PASSWORD"
    )


    # ==========================
    # SECURITY / CSRF
    # ==========================

    CSRF_ENABLED = True

    WTF_CSRF_ENABLED = True

    WTF_CSRF_TIME_LIMIT = int(
        os.environ.get(
            "WTF_CSRF_TIME_LIMIT",
            "3600"
        )
    )

    SECURITY_PASSWORD_SALT = (
        os.environ.get(
            "SECURITY_PASSWORD_SALT",
            "dev-only-change-this-salt"
        )
    )


    # ==========================
    # PDF
    # ==========================

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


    # ==========================
    # CSV / EXCEL
    # ==========================

    CSV_FILENAME = os.environ.get(
        "CSV_FILENAME",
        "Scan_Report.csv"
    )

    EXCEL_FILENAME = os.environ.get(
        "EXCEL_FILENAME",
        "Scan_Report.xlsx"
    )


    # ==========================
    # APPLICATION
    # ==========================

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