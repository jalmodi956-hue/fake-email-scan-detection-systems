from datetime import datetime

from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import (
    check_password_hash,
    generate_password_hash,
)


db = SQLAlchemy()


# ==========================
# USER MODEL
# ==========================

class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    username = db.Column(
        db.String(100),
        unique=True,
        nullable=False,
        index=True
    )

    email = db.Column(
        db.String(150),
        unique=True,
        nullable=False,
        index=True
    )

    password = db.Column(
        db.String(255),
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    last_login = db.Column(
        db.DateTime,
        nullable=True
    )

    is_verified = db.Column(
        db.Boolean,
        default=True,
        nullable=False
    )

    is_admin = db.Column(
        db.Boolean,
        default=False,
        nullable=False
    )

    is_blocked = db.Column(
        db.Boolean,
        default=False,
        nullable=False
    )

    profile_image = db.Column(
        db.String(255),
        default="default.png"
    )

    scans = db.relationship(
        "ScanHistory",
        backref="user",
        lazy=True,
        cascade="all, delete-orphan"
    )

    reports = db.relationship(
        "Report",
        backref="user",
        lazy=True,
        cascade="all, delete-orphan"
    )

    login_logs = db.relationship(
        "LoginLog",
        backref="user",
        lazy=True,
        cascade="all, delete-orphan"
    )

    settings = db.relationship(
        "UserSettings",
        backref="user",
        uselist=False,
        lazy=True,
        cascade="all, delete-orphan"
    )

    def set_password(self, password):
        self.password = generate_password_hash(
            password
        )

    def check_password(self, password):
        if not self.password or not password:
            return False

        return check_password_hash(
            self.password,
            password
        )


# ==========================
# SCAN HISTORY
# ==========================

class ScanHistory(db.Model):
    __tablename__ = "scan_history"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "users.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    email = db.Column(
        db.String(255),
        index=True
    )

    domain = db.Column(
        db.String(255),
        index=True
    )

    subject = db.Column(
        db.String(255)
    )

    content = db.Column(
        db.Text
    )

    risk_score = db.Column(
        db.Integer,
        default=0,
        nullable=False
    )

    verdict = db.Column(
        db.String(50),
        default="safe",
        nullable=False,
        index=True
    )

    ai_verdict = db.Column(
        db.String(50),
        default="UNAVAILABLE"
    )

    ai_confidence = db.Column(
        db.Integer,
        default=0
    )

    scan_time = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False,
        index=True
    )

    __table_args__ = (
        db.Index(
            "ix_scan_history_user_time",
            "user_id",
            "scan_time"
        ),
    )


# ==========================
# REPORT
# ==========================

class Report(db.Model):
    __tablename__ = "reports"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "users.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    report_name = db.Column(
        db.String(255),
        nullable=False
    )

    report_type = db.Column(
        db.String(50)
    )

    file_path = db.Column(
        db.String(500)
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False
    )


# ==========================
# USER SETTINGS
# ==========================

class UserSettings(db.Model):
    __tablename__ = "settings"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "users.id",
            ondelete="CASCADE"
        ),
        unique=True,
        nullable=False,
        index=True
    )

    dark_mode = db.Column(
        db.Boolean,
        default=True,
        nullable=False
    )

    email_notifications = db.Column(
        db.Boolean,
        default=True,
        nullable=False
    )

    language = db.Column(
        db.String(20),
        default="English",
        nullable=False
    )

    items_per_page = db.Column(
        db.Integer,
        default=10,
        nullable=False
    )


# ==========================
# LOGIN LOG
# ==========================

class LoginLog(db.Model):
    __tablename__ = "login_logs"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "users.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    ip_address = db.Column(
        db.String(100)
    )

    device = db.Column(
        db.String(255)
    )

    browser = db.Column(
        db.String(500)
    )

    login_time = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False,
        index=True
    )


# ==========================
# CONTACT MESSAGE
# ==========================

class ContactMessage(db.Model):
    __tablename__ = "contact_messages"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    name = db.Column(
        db.String(100),
        nullable=False
    )

    email = db.Column(
        db.String(150),
        nullable=False,
        index=True
    )

    subject = db.Column(
        db.String(255)
    )

    message = db.Column(
        db.Text,
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False,
        index=True
    )