# ==========================================================
# AI PHISHING EMAIL DETECTOR
# app.py (Part 1A)
# ==========================================================

# ==========================
# Standard Library
# ==========================

import os
import re
import csv
import json
import random
import string
import secrets
import sqlite3
import importlib

from datetime import datetime, timedelta
from difflib import SequenceMatcher
from io import StringIO, BytesIO
from openpyxl import Workbook
from reportlab.lib.pagesizes import A4

# ==========================
# Flask
# ==========================

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    send_file,
    jsonify
)

# ==========================
# Database
# ==========================

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func

# ==========================
# Authentication
# ==========================

from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    login_required,
    current_user
)

# ==========================
# Password Security
# ==========================

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from werkzeug.utils import secure_filename

# ==========================
# Mail
# ==========================

from flask_mail import Mail, Message

# ==========================
# CSRF
# ==========================

from flask_wtf.csrf import CSRFProtect

# ==========================
# PDF
# ==========================

from reportlab.pdfgen import canvas

# ==========================
# Local Files
# ==========================

from config import Config

from models import (
    db,
    User,
    ScanHistory,
    OTP,
    Report,
    UserSettings,
    LoginLog,
    ContactMessage
)

# ==========================================================
# Flask App
# ==========================================================

app = Flask(__name__)

app.config.from_object(Config)

# ==========================================================
# Database
# ==========================================================

db.init_app(app)

# ==========================================================
# Mail
# ==========================================================

mail = Mail(app)

# ==========================================================
# CSRF
# ==========================================================

csrf = CSRFProtect(app)

# ==========================================================
# Login Manager
# ==========================================================

login_manager = LoginManager()

login_manager.init_app(app)

login_manager.login_view = "login"

login_manager.login_message = "Please login to continue."

login_manager.login_message_category = "warning"

# ==========================================================
# Create Database
# ==========================================================

with app.app_context():
    db.create_all()

# ==========================================================
# Create Required Folders
# ==========================================================

folders = [

    app.config["UPLOAD_FOLDER"],

    app.config["EXPORT_FOLDER"],

    app.config["REPORT_FOLDER"],

    app.config["LOG_FOLDER"]

]

for folder in folders:
    os.makedirs(folder, exist_ok=True)

# ==========================================================
# Anthropic AI
# ==========================================================

anthropic = None
# ==========================================================
# Login Loader
# ==========================================================

@login_manager.user_loader
def load_user(user_id):

    return db.session.get(User, int(user_id))

# ==========================================================
# Trusted Domains
# ==========================================================

TRUSTED_DOMAINS_FILE = "trusted_domains.txt"

def load_trusted_domains():

    if not os.path.exists(TRUSTED_DOMAINS_FILE):
        return []

    with open(
        TRUSTED_DOMAINS_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        return [
            line.strip().lower()
            for line in file
            if line.strip()
        ]

trusted_domains = load_trusted_domains()

# ==========================================================
# Helper Functions
# ==========================================================

def allowed_file(filename):

    return (

        "." in filename

        and

        filename.rsplit(".", 1)[1].lower()

        in app.config["ALLOWED_EXTENSIONS"]

    )


def generate_otp():

    return "".join(

        random.choice(string.digits)

        for _ in range(6)

    )


def random_password(length=12):

    chars = (

        string.ascii_letters

        +

        string.digits

        +

        "!@#$%^&*"

    )

    return "".join(

        secrets.choice(chars)

        for _ in range(length)

    )


def send_otp(email, otp):

    try:

        sender = (
            app.config.get("MAIL_DEFAULT_SENDER")
            or app.config.get("MAIL_USERNAME")
            or "no-reply@example.com"
        )

        msg = Message(
            subject="Your OTP Code",
            sender=sender,
            recipients=[email],
            body=(
                f"Your OTP code is: {otp}.\n\n"
                "This code will expire in 10 minutes.\n"
                "If you did not request this, please ignore this message."
            )
        )

        mail.send(msg)

        return True

    except Exception as error:

        print("Send OTP Error:", error)

        return False

# ==========================================================
# END OF PART 1A
# ==========================================================

# ==========================================================
# USER SIGNUP
# ==========================================================

@app.route("/signup", methods=["GET", "POST"])
def signup():

    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":

        username = request.form.get("username", "").strip()

        email = request.form.get("email", "").strip().lower()

        password = request.form.get("password", "")

        confirm = request.form.get("confirm_password", "")

        # Validation

        if username == "" or email == "" or password == "":
            flash("All fields are required.", "danger")
            return redirect(url_for("signup"))

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("signup"))

        if len(password) < app.config["MIN_PASSWORD_LENGTH"]:
            flash("Password is too short.", "danger")
            return redirect(url_for("signup"))

        existing_email = User.query.filter_by(email=email).first()

        if existing_email:
            flash("Email already registered.", "warning")
            return redirect(url_for("signup"))

        existing_user = User.query.filter_by(username=username).first()

        if existing_user:
            flash("Username already exists.", "warning")
            return redirect(url_for("signup"))

        user = User(
            username=username,
            email=email,
            is_verified=True
        )

        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        flash(
            "Account created successfully. Please login.",
            "success"
        )

        return redirect(url_for("login"))

    return render_template("signup.html")


# ==========================================================
# LOGIN
# ==========================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()

        password = request.form.get("password", "")

        remember = request.form.get("remember")

        user = User.query.filter_by(email=email).first()

        if user is None:

            flash("Invalid Email.", "danger")

            return redirect(url_for("login"))

        if not user.check_password(password):

            flash("Invalid Password.", "danger")

            return redirect(url_for("login"))

        if getattr(user, "is_blocked", False):

            flash(
                "Your account has been blocked by admin.",
                "danger"
            )

            return redirect(url_for("login"))

        login_user(
            user,
            remember=bool(remember)
        )

        user.last_login = datetime.utcnow()

        db.session.commit()

        save_login_log(user)

        flash(
            "Login Successful.",
            "success"
        )

        return redirect(url_for("dashboard"))

    return render_template("login.html")

# ==========================================================
# LOGOUT
# ==========================================================

@app.route("/logout")
@login_required
def logout():

    logout_user()

    session.clear()

    flash(

        "Logged Out Successfully.",

        "success"

    )

    return redirect(url_for("login"))

# ==========================================================
# FORGOT PASSWORD
# ==========================================================

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()

        user = User.query.filter_by(email=email).first()

        if not user:
            flash("Email not registered.", "danger")
            return redirect(url_for("forgot_password"))

        otp = generate_otp()

        otp_record = OTP(
            email=email,
            otp=otp
        )

        db.session.add(otp_record)
        db.session.commit()

        send_otp(email, otp)

        session["reset_email"] = email

        flash(
            "OTP sent successfully.",
            "success"
        )

        return redirect(url_for("reset_password"))

    return render_template("forgot_password.html")


# ==========================================================
# RESET PASSWORD
# ==========================================================

@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():

    email = session.get("reset_email")

    if not email:
        flash("Session expired.", "warning")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":

        otp = request.form.get("otp", "").strip()

        password = request.form.get("password")

        confirm = request.form.get("confirm_password")

        if password != confirm:

            flash(
                "Passwords do not match.",
                "danger"
            )

            return redirect(url_for("reset_password"))

        if not password or len(password) < app.config["MIN_PASSWORD_LENGTH"]:

            flash(
                "Password is too short.",
                "danger"
            )

            return redirect(url_for("reset_password"))

        otp_data = OTP.query.filter_by(
            email=email,
            is_used=False
        ).order_by(
            OTP.created_at.desc()
        ).first()

        if otp_data is None:

            flash(
                "Invalid OTP.",
                "danger"
            )

            return redirect(url_for("reset_password"))

        expiry = datetime.utcnow() - otp_data.created_at

        if expiry.total_seconds() > 600:

            flash(
                "OTP Expired.",
                "danger"
            )

            return redirect(url_for("reset_password"))

        if otp_data.otp != otp:

            flash(
                "Incorrect OTP.",
                "danger"
            )

            return redirect(url_for("reset_password"))

        user = User.query.filter_by(
            email=email
        ).first()

        user.set_password(password)

        otp_data.is_used = True

        db.session.commit()

        session.pop("reset_email", None)

        flash(
            "Password Changed Successfully.",
            "success"
        )

        return redirect(url_for("login"))

    return render_template("reset_password.html")


# ==========================================================
# CHANGE PASSWORD
# ==========================================================

@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():

    if request.method == "POST":

        old_password = request.form.get("old_password")

        new_password = request.form.get("new_password")

        confirm_password = request.form.get("confirm_password")

        if not current_user.check_password(old_password):

            flash(
                "Current Password Incorrect.",
                "danger"
            )

            return redirect(url_for("change_password"))

        if new_password != confirm_password:

            flash(
                "Passwords do not match.",
                "danger"
            )

            return redirect(url_for("change_password"))

        if not new_password or len(new_password) < app.config["MIN_PASSWORD_LENGTH"]:

            flash(
                "New password is too short.",
                "danger"
            )

            return redirect(url_for("change_password"))

        current_user.set_password(new_password)

        db.session.commit()

        flash(
            "Password Updated Successfully.",
            "success"
        )

        return redirect(url_for("dashboard"))

    return render_template("change_password.html")

# ==========================================================
# HOME
# ==========================================================

@app.route("/", methods=["GET", "POST"])
@login_required
def home():

    result = ""

    email = ""

    content = ""

    risk_score = 0

    verdict = ""

    ai_result = {}

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()

        content = request.form.get("content", "").strip()

        if email == "":

            flash("Please enter email address.", "danger")

            return redirect(url_for("home"))

        if content == "":

            flash("Please enter email content.", "danger")

            return redirect(url_for("home"))

        # ==========================================
        # RULE BASED SCAN
        # ==========================================

        scan = rule_based_scan(email, content)

        risk_score = scan["risk_score"]

        verdict = score_to_verdict(risk_score)

        domain = scan["domain"]

        result = scan["result"]

        # ==========================================
        # AI ANALYSIS
        # ==========================================

        ai_result = analyze_with_ai(content)

        if ai_result["available"]:

            risk_score, verdict = merge_results(

                risk_score,

                ai_result["riskScore"]

            )

        # ==========================================
        # SAVE SCAN
        # ==========================================

        history = ScanHistory(

            user_id=current_user.id,

            email=email,

            domain=domain,

            content=content,

            risk_score=risk_score,

            verdict=verdict,

            ai_verdict=ai_result.get(

                "verdict",

                "UNAVAILABLE"

            ),

            ai_confidence=ai_result.get(

                "confidence",

                0

            )

        )

        db.session.add(history)

        db.session.commit()

        flash(

            "Email Scan Completed.",

            "success"

        )

    return render_template(

        "index.html",

        result=result,

        email=email,

        content=content,

        verdict=verdict,

        risk_score=risk_score,

        ai=ai_result

    )

# ==========================================================
# SCORE TO VERDICT
# ==========================================================

def score_to_verdict(score):

    if score <= 30:
        return "safe"

    elif score <= 60:
        return "suspicious"

    else:
        return "phishing"


# ==========================================================
# MERGE AI + RULE SCORE
# ==========================================================

def merge_results(rule_score, ai_score):

    try:

        final_score = int(
            (rule_score * 0.40) +
            (ai_score * 0.60)
        )

    except Exception:

        final_score = rule_score

    if final_score > 100:
        final_score = 100

    if final_score < 0:
        final_score = 0

    verdict = score_to_verdict(final_score)

    return final_score, verdict


# ==========================================================
# SAVE SCAN HISTORY
# ==========================================================

def save_scan(
    email,
    domain,
    content,
    risk_score,
    verdict,
    ai_verdict="UNAVAILABLE",
    ai_confidence=0
):

    try:

        history = ScanHistory(

            user_id=current_user.id,

            email=email,

            domain=domain,

            content=content,

            risk_score=risk_score,

            verdict=verdict,

            ai_verdict=ai_verdict,

            ai_confidence=ai_confidence,

            scan_time=datetime.utcnow()

        )

        db.session.add(history)

        db.session.commit()

        return True

    except Exception as e:

        db.session.rollback()

        print("Database Error :", e)

        return False


# ==========================================================
# SAVE LOGIN LOG
# ==========================================================

def save_login_log(user):

    try:

        log = LoginLog(

            user_id=user.id,

            ip_address=request.remote_addr,

            browser=request.user_agent.string,

            login_time=datetime.utcnow()

        )

        db.session.add(log)

        db.session.commit()

    except Exception:

        db.session.rollback()


# ==========================================================
# DELETE OLD OTP
# ==========================================================

def delete_old_otps(email):

    OTP.query.filter_by(

        email=email,

        is_used=True

    ).delete()

    db.session.commit()


# ==========================================================
# GET DASHBOARD COUNTS
# ==========================================================

def dashboard_counts(user_id):

    total = ScanHistory.query.filter_by(

        user_id=user_id

    ).count()

    safe = ScanHistory.query.filter_by(

        user_id=user_id,

        verdict="safe"

    ).count()

    suspicious = ScanHistory.query.filter_by(

        user_id=user_id,

        verdict="suspicious"

    ).count()

    phishing = ScanHistory.query.filter_by(

        user_id=user_id,

        verdict="phishing"

    ).count()

    return {

        "total": total,

        "safe": safe,

        "suspicious": suspicious,

        "phishing": phishing

    }

def get_monthly_scan_stats(user_id):

    dialect = db.engine.dialect.name

    if dialect == "postgresql":

        month_expression = func.to_char(
            ScanHistory.scan_time,
            "YYYY-MM"
        )

    else:

        month_expression = func.strftime(
            "%Y-%m",
            ScanHistory.scan_time
        )

    return (
        db.session.query(
            month_expression.label("month"),
            func.count(ScanHistory.id).label("total")
        )
        .filter(ScanHistory.user_id == user_id)
        .group_by(month_expression)
        .order_by(month_expression)
        .all()
    )


# ==========================================================
# END OF PART 1C-1B-1
# ==========================================================

# ==========================================================
# RULE BASED SCAN
# PART 1
# ==========================================================

def rule_based_scan(email, content):

    result = ""

    domain = ""

    risk_score = 0

    content_lower = content.lower()

    urls = re.findall(r'https?://[^\s]+', content)

    keywords = [

        "urgent",

        "verify",

        "click here",

        "login",

        "password",

        "account suspended",

        "bank",

        "prize",

        "update",

        "otp",

        "security alert",

        "payment",

        "invoice",

        "gift",

        "winner",

        "confirm account",

        "reset password",

        "limited time",

        "act now",

        "immediately"

    ]

    found_keywords = [

        word

        for word in keywords

        if word in content_lower

    ]

    # ==================================================
    # EMAIL VALIDATION
    # ==================================================

    if (

        "@" not in email

        or

        email.startswith("@")

        or

        email.endswith("@")

    ):

        return {

            "valid": False,

            "domain": "",

            "risk_score": 100,

            "result": "❌ Invalid Email Address",

            "urls": urls,

            "keywords": found_keywords

        }

    domain = email.split("@")[1].strip().lower()

    # ==================================================
    # TRUSTED DOMAIN
    # ==================================================

    if domain in trusted_domains:

        result += f"""

✅ Trusted Domain

<b>{domain}</b>

"""

    else:

        result += f"""

⚠ Unknown Domain

<b>{domain}</b>

"""

        risk_score += 30

    # ==================================================
    # SIMILAR DOMAIN DETECTION
    # ==================================================

    closest = None

    highest = 0

    for trusted in trusted_domains:

        similarity = SequenceMatcher(

            None,

            domain,

            trusted

        ).ratio()

        if similarity > highest:

            highest = similarity

            closest = trusted

    if highest >= 0.80 and domain != closest:

        result += f"""

⚠ Looks Similar To

<b>{closest}</b>

Similarity : {round(highest*100)}%

"""

        risk_score += 20

        # ==================================================
    # SUSPICIOUS KEYWORDS
    # ==================================================

    if found_keywords:

        risk_score += len(found_keywords) * 5

        result += "<br><br><b>⚠ Suspicious Keywords:</b><br>"

        for word in found_keywords:

            result += f"• {word}<br>"

    else:

        result += "<br><br>✅ No Suspicious Keywords Found"

    # ==================================================
    # URL DETECTION
    # ==================================================

    if urls:

        result += "<br><br><b>🌐 URLs Found:</b><br>"

        for url in urls:

            result += f"{url}<br>"

            if not url.startswith("https://"):

                risk_score += 10

                result += "❌ Not Using HTTPS<br>"

            if len(url) > 80:

                risk_score += 10

                result += "⚠ Long URL Detected<br>"

            ip_pattern = r"(https?://)?(\d{1,3}\.){3}\d{1,3}"

            if re.search(ip_pattern, url):

                risk_score += 20

                result += "⚠ IP Address URL Detected<br>"

            if "@" in url:

                risk_score += 10

                result += "⚠ '@' Symbol Found<br>"

            if url.count("//") > 1:

                risk_score += 10

                result += "⚠ Multiple // Found<br>"

            if "-" in url:

                risk_score += 5

                result += "⚠ Hyphenated Domain<br>"

    else:

        result += "<br><br>✅ No URL Found"

    # ==================================================
    # FINAL SCORE
    # ==================================================

    if risk_score > 100:

        risk_score = 100

    if risk_score < 0:

        risk_score = 0

    # ==================================================
    # RETURN
    # ==================================================

    return {

        "valid": True,

        "domain": domain,

        "risk_score": risk_score,

        "result": result,

        "urls": urls,

        "keywords": found_keywords

    }

# ==================================================
# END OF RULE BASED SCAN
# ==================================================

# ==========================================================
# AI ANALYSIS
# PART 1
# ==========================================================

SYSTEM_PROMPT = """
You are a cybersecurity expert specializing in phishing email detection.

Analyze the email and return ONLY valid JSON.

{
    "verdict":"SAFE | SUSPICIOUS | PHISHING",
    "confidence":0,
    "riskScore":0,
    "summary":"",
    "indicators":[
        {
            "type":"",
            "label":"",
            "detail":"",
            "severity":""
        }
    ],
    "recommendation":""
}
"""


def analyze_with_ai(email_text):

    api_key = app.config.get("ANTHROPIC_API_KEY")

    # --------------------------------------
    # SDK Installed?
    # --------------------------------------

    if anthropic is None:

        return {
            "available": False,
            "verdict": "UNAVAILABLE",
            "confidence": 0,
            "riskScore": 0,
            "summary": "Anthropic SDK not installed.",
            "indicators": [],
            "recommendation": "Install anthropic package."
        }

    # --------------------------------------
    # API KEY
    # --------------------------------------

    if not api_key:

        return {
            "available": False,
            "verdict": "UNAVAILABLE",
            "confidence": 0,
            "riskScore": 0,
            "summary": "API Key Missing.",
            "indicators": [],
            "recommendation": "Configure ANTHROPIC_API_KEY."
        }

    try:

        # --------------------------------------
        # Claude Client
        # --------------------------------------

        client = anthropic.Anthropic(
            api_key=api_key
        )

        # --------------------------------------
        # API REQUEST
        # --------------------------------------

        message = client.messages.create(

            model=app.config["ANTHROPIC_MODEL"],

            max_tokens=1200,

            temperature=0,

            system=SYSTEM_PROMPT,

            messages=[
                {
                    "role": "user",
                    "content": f"""
Analyze this email carefully.

Email Content:

{email_text}

Return JSON only.
"""
                }
            ]
        )

        raw_response = message.content[0].text.strip()

        raw_response = (

            raw_response

            .replace("```json", "")

            .replace("```", "")

            .strip()

        )

        # --------------------------------------
        # JSON PARSING
        # --------------------------------------

        try:

            result = json.loads(raw_response)

        except json.JSONDecodeError:

            return {

                "available": False,

                "verdict": "UNAVAILABLE",

                "confidence": 0,

                "riskScore": 0,

                "summary": "AI returned invalid JSON.",

                "indicators": [],

                "recommendation": "Retry AI analysis."

            }

        # --------------------------------------
        # EXTRACT AI RESULT
        # --------------------------------------

        verdict = result.get(

            "verdict",

            "SUSPICIOUS"

        )

        confidence = int(

            result.get(

                "confidence",

                0

            )

        )

        risk_score = int(

            result.get(

                "riskScore",

                0

            )

        )

        summary = result.get(

            "summary",

            "No summary available."

        )

        indicators = result.get(

            "indicators",

            []

        )

        recommendation = result.get(

            "recommendation",

            "Be cautious."

        )

        # --------------------------------------
        # LIMIT VALUES
        # --------------------------------------

        confidence = max(

            0,

            min(

                confidence,

                100

            )

        )

        risk_score = max(

            0,

            min(

                risk_score,

                100

            )

        )

        # --------------------------------------
        # RETURN AI RESULT
        # --------------------------------------

        return {

            "available": True,

            "verdict": verdict,

            "confidence": confidence,

            "riskScore": risk_score,

            "summary": summary,

            "indicators": indicators,

            "recommendation": recommendation

        }

    except anthropic.AuthenticationError:
        return {
            "available": False,
            "verdict": "UNAVAILABLE",
            "confidence": 0,
            "riskScore": 0,
            "summary": "Invalid Anthropic API Key.",
            "indicators": [],
            "recommendation": "Check your API Key."
        }

    except anthropic.RateLimitError:
        return {
            "available": False,
            "verdict": "UNAVAILABLE",
            "confidence": 0,
            "riskScore": 0,
            "summary": "Rate Limit Exceeded.",
            "indicators": [],
            "recommendation": "Please try again later."
        }

    except anthropic.APIConnectionError:
        return {
            "available": False,
            "verdict": "UNAVAILABLE",
            "confidence": 0,
            "riskScore": 0,
            "summary": "Unable to connect to AI server.",
            "indicators": [],
            "recommendation": "Check your internet connection."
        }

    except anthropic.APIStatusError as e:
        return {
            "available": False,
            "verdict": "UNAVAILABLE",
            "confidence": 0,
            "riskScore": 0,
            "summary": f"Anthropic API Error ({e.status_code}).",
            "indicators": [],
            "recommendation": "Retry after some time."
        }

    except json.JSONDecodeError:
        return {
            "available": False,
            "verdict": "UNAVAILABLE",
            "confidence": 0,
            "riskScore": 0,
            "summary": "Invalid JSON received from AI.",
            "indicators": [],
            "recommendation": "Retry AI analysis."
        }

    except Exception as e:
        print("AI Error :", e)
        return {
            "available": False,
            "verdict": "UNAVAILABLE",
            "confidence": 0,
            "riskScore": 0,
            "summary": str(e),
            "indicators": [],
            "recommendation": "Rule-Based Detection Used."
        }

@app.route("/dashboard")
@login_required
def dashboard():

    # ------------------------------------------
    # TOTAL SCANS
    # ------------------------------------------

    total_scans = ScanHistory.query.filter_by(
    user_id=current_user.id
    ).count()

    # ------------------------------------------
    # SAFE EMAILS
    # ------------------------------------------

    safe_count = ScanHistory.query.filter_by(
        user_id=current_user.id,
        verdict="safe"
    ).count()

    # ------------------------------------------
    # SUSPICIOUS EMAILS
    # ------------------------------------------

    suspicious_count = ScanHistory.query.filter_by(
        user_id=current_user.id,
        verdict="suspicious"
    ).count()

    # ------------------------------------------
    # PHISHING EMAILS
    # ------------------------------------------

    phishing_count = ScanHistory.query.filter_by(
        user_id=current_user.id,
        verdict="phishing"
    ).count()

    # ------------------------------------------
    # RECENT SCANS
    # ------------------------------------------

    recent_scans = (
        ScanHistory.query
        .filter_by(user_id=current_user.id)
        .order_by(ScanHistory.scan_time.desc())
        .limit(10)
        .all()
    )

    # ------------------------------------------
    # LAST SCAN
    # ------------------------------------------

    last_scan = (
        ScanHistory.query
        .filter_by(user_id=current_user.id)
        .order_by(ScanHistory.scan_time.desc())
        .first()
    )

    # ------------------------------------------
    # HIGH RISK SCANS
    # ------------------------------------------

    high_risk = (
        ScanHistory.query
        .filter(
            ScanHistory.user_id == current_user.id,
            ScanHistory.risk_score >= 80
        )
        .count()
    )

    # ------------------------------------------
    # LOW RISK SCANS
    # ------------------------------------------

    low_risk = (
        ScanHistory.query
        .filter(
            ScanHistory.user_id == current_user.id,
            ScanHistory.risk_score < 30
        )
        .count()
    )

    # ------------------------------------------
    # DASHBOARD
    # ------------------------------------------

    # ==========================================================
    # DASHBOARD ANALYTICS
    # PART 2
    # ==========================================================

    from sqlalchemy import func

    # ------------------------------------------
    # AVERAGE RISK SCORE
    # ------------------------------------------

    average_risk = db.session.query(

        func.avg(ScanHistory.risk_score)

    ).filter(

        ScanHistory.user_id == current_user.id

    ).scalar()

    if average_risk is None:
        average_risk = 0
    else:
        average_risk = round(float(average_risk), 2)

    # ------------------------------------------
    # HIGHEST RISK SCORE
    # ------------------------------------------

    highest_risk = db.session.query(

        func.max(ScanHistory.risk_score)

    ).filter(

        ScanHistory.user_id == current_user.id

    ).scalar()

    highest_risk = highest_risk or 0

    # ------------------------------------------
    # LOWEST RISK SCORE
    # ------------------------------------------

    lowest_risk = db.session.query(

        func.min(ScanHistory.risk_score)

    ).filter(

        ScanHistory.user_id == current_user.id

    ).scalar()

    lowest_risk = lowest_risk or 0

    # ------------------------------------------
    # TOTAL UNIQUE DOMAINS
    # ------------------------------------------

    unique_domains = db.session.query(

        func.count(

            func.distinct(

                ScanHistory.domain

            )

        )

    ).filter(

        ScanHistory.user_id == current_user.id

    ).scalar()

    # ------------------------------------------
    # TOP DANGEROUS DOMAINS
    # ------------------------------------------

    top_domains = (

        db.session.query(

            ScanHistory.domain,

            func.count(

                ScanHistory.id

            ).label("total")

        )

        .filter(

            ScanHistory.user_id == current_user.id

        )

        .group_by(

            ScanHistory.domain

        )

        .order_by(

            func.count(

                ScanHistory.id

            ).desc()

        )

        .limit(5)

        .all()

    )

    # ------------------------------------------
    # CHART DATA
    # ------------------------------------------

    chart_labels = [

        "Safe",

        "Suspicious",

        "Phishing"

    ]

    chart_values = [

        safe_count,

        suspicious_count,

        phishing_count

    ]

    # ------------------------------------------
    # MONTHLY STATISTICS
    # ------------------------------------------

    monthly_stats = get_monthly_scan_stats(
        current_user.id
    )

    month_labels = [

        row.month

        for row in monthly_stats

    ]

    month_values = [

        row.total

        for row in monthly_stats

    ]

    week_labels = []

    week_values = []

    return render_template(
        "dashboard.html",
        total_scans=total_scans,
        safe_count=safe_count,
        suspicious_count=suspicious_count,
        phishing_count=phishing_count,
        high_risk=high_risk,
        low_risk=low_risk,
        recent_scans=recent_scans,
        last_scan=last_scan,
        average_risk=average_risk,
        highest_risk=highest_risk,
        lowest_risk=lowest_risk,
        unique_domains=unique_domains,
        top_domains=top_domains,
        chart_labels=chart_labels,
        chart_values=chart_values,
        month_labels=month_labels,
        month_values=month_values,
        week_labels=week_labels,
        week_values=week_values,
    )

# ==========================================================
# END OF PART 1C-2B
# ==========================================================
# ==========================================================
# DASHBOARD SEARCH + FILTER + PAGINATION
# PART 1C-2C
# ==========================================================

# ------------------------------------------
# SEARCH PARAMETERS
# ------------------------------------------
@app.route(
    "/delete/<int:scan_id>",
    methods=["POST"]
)
@login_required
def delete_scan(scan_id):

    scan = ScanHistory.query.filter_by(

        id=scan_id,

        user_id=current_user.id

    ).first_or_404()

    try:

        db.session.delete(scan)

        db.session.commit()

        flash(
            "Scan deleted successfully.",
            "success"
        )

    except Exception as error:

        db.session.rollback()

        print("Delete Scan Error:", error)

        flash(
            "Unable to delete scan.",
            "danger"
        )

    return redirect(
        url_for("dashboard")
    )


# ==========================================================
# DASHBOARD JSON API
# ==========================================================

@app.route("/api/dashboard")
@login_required
def dashboard_api():

    counts = dashboard_counts(
        current_user.id
    )

    average = db.session.query(

        func.avg(
            ScanHistory.risk_score
        )

        ).filter(

        ScanHistory.user_id
        == current_user.id

        ).scalar() or 0

    latest_scans = (

        ScanHistory.query

        .filter_by(
            user_id=current_user.id
        )

        .order_by(
            ScanHistory.scan_time.desc()
        )

        .limit(5)

        .all()

    )

    scan_data = []

    for scan in latest_scans:

        scan_data.append({

            "id": scan.id,

            "email": scan.email,

            "domain": scan.domain,

            "risk_score": scan.risk_score,

            "verdict": scan.verdict,

            "scan_time": (
                scan.scan_time.isoformat()
                if scan.scan_time
                else None
            )

        })

    return jsonify({

        "success": True,

        "statistics": {

            "total": counts["total"],

            "safe": counts["safe"],

            "suspicious": counts["suspicious"],

            "phishing": counts["phishing"],

            "average_risk": round(
                float(average),
                2
            )

        },

        "recent_scans": scan_data

    })


# ==========================================================
# SCAN DETAILS API
# ==========================================================

@app.route("/scan/<int:scan_id>")
@login_required
def scan_details(scan_id):

    scan = ScanHistory.query.filter_by(

        id=scan_id,

        user_id=current_user.id

    ).first_or_404()

    return jsonify({

        "id": scan.id,

        "email": scan.email,

        "domain": scan.domain,

        "content": scan.content,

        "risk_score": scan.risk_score,

        "verdict": scan.verdict,

        "ai_verdict": scan.ai_verdict,

        "ai_confidence": scan.ai_confidence,

        "scan_time": (
            scan.scan_time.isoformat()
            if scan.scan_time
            else None
        )

    })
    # ==========================================================
# PART 1C-3
# HISTORY ROUTE + SEARCH + FILTER + PAGINATION
# ==========================================================

@app.route("/history")
@login_required
def history():

    # ------------------------------------------
    # GET FILTER VALUES
    # ------------------------------------------

    search = request.args.get(
        "search",
        ""
    ).strip()

    verdict_filter = request.args.get(
        "verdict",
        ""
    ).strip().lower()

    date_filter = request.args.get(
        "date",
        ""
    ).strip()

    page = request.args.get(
        "page",
        1,
        type=int
    )

    per_page = app.config.get(
        "ITEMS_PER_PAGE",
        10
    )

    # ------------------------------------------
    # BASE QUERY
    # ------------------------------------------

    query = ScanHistory.query.filter_by(
        user_id=current_user.id
    )

    # ------------------------------------------
    # SEARCH EMAIL / DOMAIN
    # ------------------------------------------

    if search:

        search_value = f"%{search}%"

        query = query.filter(

            db.or_(

                ScanHistory.email.ilike(
                    search_value
                ),

                ScanHistory.domain.ilike(
                    search_value
                )

            )

        )

    # ------------------------------------------
    # VERDICT FILTER
    # ------------------------------------------

    allowed_verdicts = [
        "safe",
        "suspicious",
        "phishing"
    ]

    if verdict_filter in allowed_verdicts:

        query = query.filter(

            ScanHistory.verdict
            == verdict_filter

        )

    # ------------------------------------------
    # DATE FILTER
    # ------------------------------------------

    if date_filter:

        try:

            selected_date = datetime.strptime(
                date_filter,
                "%Y-%m-%d"
            ).date()

            query = query.filter(

                func.date(
                    ScanHistory.scan_time
                )
                == selected_date.isoformat()

            )

        except ValueError:

            flash(
                "Invalid date selected.",
                "warning"
            )

    # ------------------------------------------
    # ORDER HISTORY
    # ------------------------------------------

    query = query.order_by(

        ScanHistory.scan_time.desc()

    )

    # ------------------------------------------
    # PAGINATION
    # ------------------------------------------

    pagination = query.paginate(

        page=page,

        per_page=per_page,

        error_out=False

    )

    scans = pagination.items

    page = pagination.page

    total_pages = pagination.pages

    # ------------------------------------------
    # USER TOTAL COUNTS
    # ------------------------------------------

    total_scans = ScanHistory.query.filter_by(

        user_id=current_user.id

    ).count()

    safe_count = ScanHistory.query.filter_by(

        user_id=current_user.id,

        verdict="safe"

    ).count()

    suspicious_count = ScanHistory.query.filter_by(

        user_id=current_user.id,

        verdict="suspicious"

    ).count()

    phishing_count = ScanHistory.query.filter_by(

        user_id=current_user.id,

        verdict="phishing"

    ).count()

    # ------------------------------------------
    # MONTHLY CHART STATISTICS
    # ------------------------------------------

    monthly_stats = get_monthly_scan_stats(
        current_user.id
    )

    month_labels = [

        row.month

        for row in monthly_stats

    ]

    month_values = [

        row.total

        for row in monthly_stats

    ]

    # ------------------------------------------
    # FINAL HISTORY RETURN
    # ------------------------------------------

    return render_template(

        "history.html",

        scans=scans,

        pagination=pagination,

        page=page,

        total_pages=total_pages,

        total_scans=total_scans,

        safe_count=safe_count,

        suspicious_count=suspicious_count,

        phishing_count=phishing_count,

        month_labels=month_labels,

        month_values=month_values,

        search=search,

        verdict_filter=verdict_filter,

        date_filter=date_filter

    )


# ==========================================================
# DELETE HISTORY SCAN
# ==========================================================

@app.route(
    "/history/delete/<int:scan_id>",
    methods=["POST"]
)
@login_required
def history_delete_scan(scan_id):

    scan = ScanHistory.query.filter_by(

        id=scan_id,

        user_id=current_user.id

    ).first_or_404()

    try:

        db.session.delete(scan)

        db.session.commit()

        flash(
            "Scan deleted successfully.",
            "success"
        )

    except Exception as error:

        db.session.rollback()

        print(
            "History Delete Error:",
            error
        )

        flash(
            "Unable to delete scan.",
            "danger"
        )

    return redirect(
        url_for("history")
    )


# ==========================================================
# CLEAR USER HISTORY
# ==========================================================

@app.route(
    "/history/clear",
    methods=["POST"]
)
@login_required
def clear_history():

    try:

        ScanHistory.query.filter_by(

            user_id=current_user.id

        ).delete(
            synchronize_session=False
        )

        db.session.commit()

        flash(
            "Scan history cleared successfully.",
            "success"
        )

    except Exception as error:

        db.session.rollback()

        print(
            "Clear History Error:",
            error
        )

        flash(
            "Unable to clear history.",
            "danger"
        )

    return redirect(
        url_for("history")
    )


# ==========================================================
# HISTORY JSON API
# ==========================================================

@app.route("/api/history")
@login_required
def history_api():

    scans = (

        ScanHistory.query

        .filter_by(
            user_id=current_user.id
        )

        .order_by(
            ScanHistory.scan_time.desc()
        )

        .limit(100)

        .all()

    )

    data = []

    for scan in scans:

        data.append({

            "id": scan.id,

            "email": scan.email,

            "domain": scan.domain,

            "risk_score": scan.risk_score,

            "verdict": scan.verdict,

            "ai_verdict": scan.ai_verdict,

            "ai_confidence": scan.ai_confidence,

            "scan_time": (

                scan.scan_time.isoformat()

                if scan.scan_time

                else None

            )

        })

    return jsonify({

        "success": True,

        "total": len(data),

        "scans": data

    })


# ==========================================================
# END OF PART 1C-3
# ==========================================================

# ==========================================================
# PART 1C-4
# PDF + CSV + EXCEL EXPORT
# ==========================================================


# ==========================================================
# CSV EXPORT
# ==========================================================

@app.route("/export")
@login_required
def export_csv():

    scans = (
        ScanHistory.query
        .filter_by(user_id=current_user.id)
        .order_by(ScanHistory.scan_time.desc())
        .all()
    )

    output = StringIO()

    writer = csv.writer(output)

    writer.writerow([
        "ID",
        "Email",
        "Domain",
        "Risk Score",
        "Verdict",
        "AI Verdict",
        "AI Confidence",
        "Scan Time"
    ])

    for scan in scans:

        writer.writerow([
            scan.id,
            scan.email or "",
            scan.domain or "",
            scan.risk_score,
            scan.verdict or "",
            scan.ai_verdict or "",
            scan.ai_confidence or 0,
            (
                scan.scan_time.strftime("%Y-%m-%d %H:%M:%S")
                if scan.scan_time
                else ""
            )
        ])

    file_data = BytesIO(
        output.getvalue().encode("utf-8-sig")
    )

    file_data.seek(0)

    output.close()

    return send_file(
        file_data,
        mimetype="text/csv",
        as_attachment=True,
        download_name="scan_history.csv"
    )


# ==========================================================
# EXCEL EXPORT
# ==========================================================

@app.route("/excel")
@login_required
def export_excel():

    scans = (
        ScanHistory.query
        .filter_by(user_id=current_user.id)
        .order_by(ScanHistory.scan_time.desc())
        .all()
    )

    workbook = Workbook()

    sheet = workbook.active

    sheet.title = "Scan History"

    headers = [
        "ID",
        "Email",
        "Domain",
        "Risk Score",
        "Verdict",
        "AI Verdict",
        "AI Confidence",
        "Scan Time"
    ]

    sheet.append(headers)

    for scan in scans:

        sheet.append([
            scan.id,
            scan.email or "",
            scan.domain or "",
            scan.risk_score,
            scan.verdict or "",
            scan.ai_verdict or "",
            scan.ai_confidence or 0,
            (
                scan.scan_time.strftime("%Y-%m-%d %H:%M:%S")
                if scan.scan_time
                else ""
            )
        ])

    widths = {
        "A": 10,
        "B": 35,
        "C": 30,
        "D": 15,
        "E": 18,
        "F": 18,
        "G": 18,
        "H": 25
    }

    for column, width in widths.items():

        sheet.column_dimensions[column].width = width

    output = BytesIO()

    workbook.save(output)

    output.seek(0)

    return send_file(
        output,
        mimetype=(
            "application/vnd.openxmlformats-officedocument."
            "spreadsheetml.sheet"
        ),
        as_attachment=True,
        download_name="scan_history.xlsx"
    )


# ==========================================================
# PDF EXPORT
# ==========================================================

@app.route("/pdf")
@login_required
def export_pdf():

    scans = (
        ScanHistory.query
        .filter_by(user_id=current_user.id)
        .order_by(ScanHistory.scan_time.desc())
        .all()
    )

    output = BytesIO()

    pdf = canvas.Canvas(
        output,
        pagesize=A4
    )

    width, height = A4

    # ------------------------------------------
    # PDF HEADER FUNCTION
    # ------------------------------------------

    def draw_header():

        pdf.setFont(
            "Helvetica-Bold",
            17
        )

        pdf.drawString(
            40,
            height - 45,
            "AI Phishing Email Detector"
        )

        pdf.setFont(
            "Helvetica",
            10
        )

        pdf.drawString(
            40,
            height - 65,
            "Scan History Security Report"
        )

        pdf.drawString(
            40,
            height - 82,
            f"User: {current_user.username}"
        )

        pdf.drawString(
            40,
            height - 99,
            (
                "Generated: "
                + datetime.utcnow().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            )
        )

        pdf.setFont(
            "Helvetica-Bold",
            8
        )

        pdf.drawString(
            35,
            height - 135,
            "Email"
        )

        pdf.drawString(
            220,
            height - 135,
            "Domain"
        )

        pdf.drawString(
            355,
            height - 135,
            "Risk"
        )

        pdf.drawString(
            400,
            height - 135,
            "Verdict"
        )

        pdf.drawString(
            485,
            height - 135,
            "Date"
        )

        pdf.line(
            35,
            height - 140,
            width - 35,
            height - 140
        )

    # ------------------------------------------
    # FIRST PAGE HEADER
    # ------------------------------------------

    draw_header()

    y = height - 160

    pdf.setFont(
        "Helvetica",
        8
    )

    # ------------------------------------------
    # SCAN DATA
    # ------------------------------------------

    for scan in scans:

        if y < 55:

            pdf.showPage()

            draw_header()

            y = height - 160

            pdf.setFont(
                "Helvetica",
                8
            )

        email_text = (
            scan.email[:30]
            if scan.email
            else ""
        )

        domain_text = (
            scan.domain[:20]
            if scan.domain
            else ""
        )

        pdf.drawString(
            35,
            y,
            email_text
        )

        pdf.drawString(
            220,
            y,
            domain_text
        )

        pdf.drawString(
            355,
            y,
            f"{scan.risk_score}%"
        )

        pdf.drawString(
            400,
            y,
            str(scan.verdict or "").upper()
        )

        scan_date = (
            scan.scan_time.strftime("%Y-%m-%d")
            if scan.scan_time
            else ""
        )

        pdf.drawString(
            485,
            y,
            scan_date
        )

        y -= 17

    # ------------------------------------------
    # EMPTY HISTORY
    # ------------------------------------------

    if not scans:

        pdf.setFont(
            "Helvetica",
            11
        )

        pdf.drawString(
            40,
            y,
            "No scan history available."
        )

    # ------------------------------------------
    # FOOTER
    # ------------------------------------------

    pdf.setFont(
        "Helvetica",
        8
    )

    pdf.drawString(
        40,
        25,
        "Generated by AI Phishing Email Detector"
    )

    pdf.save()

    output.seek(0)

    return send_file(
        output,
        mimetype="application/pdf",
        as_attachment=True,
        download_name="scan_history.pdf"
    )


# ==========================================================
# END OF PART 1C-4
# ==========================================================

# ==========================================================
# PART 2A
# PROFILE + USER SETTINGS
# ==========================================================


# ==========================================================
# USER PROFILE
# ==========================================================

@app.route("/profile")
@login_required
def profile():

    total_scans = ScanHistory.query.filter_by(
        user_id=current_user.id
    ).count()

    safe_count = ScanHistory.query.filter_by(
        user_id=current_user.id,
        verdict="safe"
    ).count()

    suspicious_count = ScanHistory.query.filter_by(
        user_id=current_user.id,
        verdict="suspicious"
    ).count()

    phishing_count = ScanHistory.query.filter_by(
        user_id=current_user.id,
        verdict="phishing"
    ).count()

    login_logs = (
        LoginLog.query
        .filter_by(user_id=current_user.id)
        .order_by(LoginLog.login_time.desc())
        .limit(10)
        .all()
    )

    return render_template(
        "profile.html",
        total_scans=total_scans,
        safe_count=safe_count,
        suspicious_count=suspicious_count,
        phishing_count=phishing_count,
        login_logs=login_logs
    )


# ==========================================================
# UPDATE PROFILE
# ==========================================================

@app.route(
    "/profile/update",
    methods=["POST"]
)
@login_required
def update_profile():

    username = request.form.get(
        "username",
        ""
    ).strip()

    email = request.form.get(
        "email",
        ""
    ).strip().lower()

    if not username or not email:

        flash(
            "Username and email are required.",
            "danger"
        )

        return redirect(
            url_for("profile")
        )

    email_exists = User.query.filter(
        User.email == email,
        User.id != current_user.id
    ).first()

    if email_exists:

        flash(
            "Email already registered.",
            "warning"
        )

        return redirect(
            url_for("profile")
        )
    
    if "@" not in email or "." not in email.split("@")[-1]:

        flash(
            "Please enter a valid email address.",
            "danger"
    )

        return redirect(
            url_for("profile")
        )

    username_exists = User.query.filter(
        User.username == username,
        User.id != current_user.id
    ).first()

    if username_exists:

        flash(
            "Username already exists.",
            "warning"
        )

        return redirect(
            url_for("profile")
        )

    try:

        current_user.username = username

        current_user.email = email

        db.session.commit()

        flash(
            "Profile updated successfully.",
            "success"
        )

    except Exception as error:

        db.session.rollback()

        print(
            "Profile Update Error:",
            error
        )

        flash(
            "Unable to update profile.",
            "danger"
        )

    return redirect(
        url_for("profile")
    )


# ==========================================================
# SETTINGS PAGE
# ==========================================================

@app.route("/settings")
@login_required
def settings():

    user_settings = UserSettings.query.filter_by(
        user_id=current_user.id
    ).first()

    if user_settings is None:

        user_settings = UserSettings(
            user_id=current_user.id
        )

        db.session.add(user_settings)

        db.session.commit()

    return render_template(
        "settings.html",
        settings=user_settings
    )


# ==========================================================
# UPDATE SETTINGS
# ==========================================================

@app.route(
    "/settings/update",
    methods=["POST"]
)
@login_required
def update_settings():

    user_settings = UserSettings.query.filter_by(
        user_id=current_user.id
    ).first()

    try:

        if user_settings is None:

            user_settings = UserSettings(
                user_id=current_user.id
            )

            db.session.add(
                user_settings
            )

        user_settings.dark_mode = (
            request.form.get("dark_mode")
            == "on"
        )

        user_settings.email_notifications = (
            request.form.get(
                "email_notifications"
            )
            == "on"
        )

        db.session.commit()

        flash(
            "Settings updated successfully.",
            "success"
        )

    except Exception as error:

        db.session.rollback()

        print(
            "Settings Update Error:",
            error
        )

        flash(
            "Unable to update settings.",
            "danger"
        )

    return redirect(
        url_for("settings")
    )


# ==========================================================
# DELETE USER ACCOUNT
# ==========================================================

@app.route(
    "/profile/delete-account",
    methods=["POST"]
)
@login_required
def delete_account():

    user = User.query.get_or_404(
        current_user.id
    )

    try:

        # Delete Scan History

        ScanHistory.query.filter_by(
            user_id=user.id
        ).delete(
            synchronize_session=False
        )

        # Delete Login Logs

        LoginLog.query.filter_by(
            user_id=user.id
        ).delete(
            synchronize_session=False
        )

        # Delete Settings

        UserSettings.query.filter_by(
            user_id=user.id
        ).delete(
            synchronize_session=False
        )

        # Logout Before Delete

        logout_user()

        # Delete User

        db.session.delete(user)

        db.session.commit()

        session.clear()

        flash(
            "Account deleted successfully.",
            "success"
        )

        return redirect(
            url_for("signup")
        )

    except Exception as error:

        db.session.rollback()

        print(
            "Delete Account Error:",
            error
        )

        flash(
            "Unable to delete account.",
            "danger"
        )

        return redirect(
            url_for("profile")
        )


# ==========================================================
# USER PROFILE API
# ==========================================================

@app.route("/api/profile")
@login_required
def profile_api():

    total_scans = ScanHistory.query.filter_by(
        user_id=current_user.id
    ).count()

    return jsonify({

        "success": True,

        "user": {

            "id": current_user.id,

            "username": current_user.username,

            "email": current_user.email

        },

        "statistics": {

            "total_scans": total_scans

        }

    })

# ==========================================================
# END OF PART 2A
# ==========================================================
# ==========================================================
# PART 2C
# CONTACT + API + ERROR HANDLERS + FINAL INITIALIZATION
# ==========================================================


# ==========================================================
# CONTACT PAGE
# ==========================================================

@app.route("/contact", methods=["GET", "POST"])
def contact():

    if request.method == "POST":

        name = request.form.get(
            "name",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        subject = request.form.get(
            "subject",
            ""
        ).strip()

        message_text = request.form.get(
            "message",
            ""
        ).strip()

        # ------------------------------------------
        # VALIDATION
        # ------------------------------------------

        if not name or not email or not message_text:

            flash(
                "Name, email and message are required.",
                "danger"
            )

            return redirect(
                url_for("contact")
            )

        if "@" not in email:

            flash(
                "Please enter a valid email address.",
                "danger"
            )

            return redirect(
                url_for("contact")
            )

        # ------------------------------------------
        # SAVE CONTACT MESSAGE
        # ------------------------------------------

        try:

            contact_message = ContactMessage(

                name=name,

                email=email,

                subject=subject,

                message=message_text

            )

            db.session.add(
                contact_message
            )

            db.session.commit()

            flash(
                "Message sent successfully.",
                "success"
            )

            return redirect(
                url_for("contact")
            )

        except Exception as error:

            db.session.rollback()

            print(
                "Contact Error:",
                error
            )

            flash(
                "Unable to send message.",
                "danger"
            )

    return render_template(
        "contact.html"
    )


# ==========================================================
# SYSTEM STATUS API
# ==========================================================

@app.route("/api/status")
def api_status():

    try:

        db.session.execute(
            db.text("SELECT 1")
        )

        database_status = "online"

    except Exception:

        database_status = "offline"

    ai_status = bool(
        anthropic
        and app.config.get(
            "ANTHROPIC_API_KEY"
        )
    )

    return jsonify({

        "success": True,

        "application": (
            "AI Phishing Email Detector"
        ),

        "status": "online",

        "database": database_status,

        "ai": (
            "configured"
            if ai_status
            else "unavailable"
        ),

        "timestamp": datetime.utcnow().isoformat()

    })


# ==========================================================
# APPLICATION STATISTICS API
# ==========================================================

@app.route("/api/statistics")
@login_required
def statistics_api():

    total_scans = ScanHistory.query.filter_by(
        user_id=current_user.id
    ).count()

    safe_count = ScanHistory.query.filter_by(
        user_id=current_user.id,
        verdict="safe"
    ).count()

    suspicious_count = ScanHistory.query.filter_by(
        user_id=current_user.id,
        verdict="suspicious"
    ).count()

    phishing_count = ScanHistory.query.filter_by(
        user_id=current_user.id,
        verdict="phishing"
    ).count()

    average_risk = db.session.query(

        func.avg(
            ScanHistory.risk_score
        )

    ).filter(

        ScanHistory.user_id
        == current_user.id

    ).scalar() or 0

    return jsonify({

        "success": True,

        "statistics": {

            "total_scans": total_scans,

            "safe": safe_count,

            "suspicious": suspicious_count,

            "phishing": phishing_count,

            "average_risk": round(
                float(average_risk),
                2
            )

        }

    })


# ==========================================================
# CURRENT USER API
# ==========================================================

@app.route("/api/me")
@login_required
def current_user_api():

    return jsonify({

        "success": True,

        "user": {

            "id": current_user.id,

            "username": current_user.username,

            "email": current_user.email,

            "is_verified": getattr(
                current_user,
                "is_verified",
                False
            ),

            "is_admin": getattr(
                current_user,
                "is_admin",
                False
            ),

            "is_blocked": getattr(
                current_user,
                "is_blocked",
                False
            )

        }

    })


# ==========================================================
# HEALTH CHECK
# ==========================================================

@app.route("/health")
def health_check():

    return jsonify({

        "status": "healthy",

        "service": (
            "AI Phishing Email Detector"
        )

    }), 200


# ==========================================================
# 400 ERROR
# ==========================================================

@app.errorhandler(400)
def bad_request(error):

    return render_template(

        "error.html",

        code=400,

        title="Bad Request",

        message=(
            "The request could not be processed."
        )

    ), 400


# ==========================================================
# 401 ERROR
# ==========================================================

@app.errorhandler(401)
def unauthorized(error):

    return render_template(

        "error.html",

        code=401,

        title="Unauthorized",

        message=(
            "Please login to access this page."
        )

    ), 401


# ==========================================================
# 403 ERROR
# ==========================================================

@app.errorhandler(403)
def forbidden(error):

    return render_template(

        "error.html",

        code=403,

        title="Access Denied",

        message=(
            "You do not have permission "
            "to access this page."
        )

    ), 403


# ==========================================================
# 404 ERROR
# ==========================================================

@app.errorhandler(404)
def page_not_found(error):

    return render_template(

        "error.html",

        code=404,

        title="Page Not Found",

        message=(
            "The requested page was not found."
        )

    ), 404


# ==========================================================
# 405 ERROR
# ==========================================================

@app.errorhandler(405)
def method_not_allowed(error):

    return render_template(

        "error.html",

        code=405,

        title="Method Not Allowed",

        message=(
            "This request method is not allowed."
        )

    ), 405


# ==========================================================
# 500 ERROR
# ==========================================================

@app.errorhandler(500)
def internal_server_error(error):

    db.session.rollback()

    print(
        "Internal Server Error:",
        error
    )

    return render_template(

        "error.html",

        code=500,

        title="Internal Server Error",

        message=(
            "Something went wrong. "
            "Please try again later."
        )

    ), 500


# ==========================================================
# TEMPLATE GLOBAL VARIABLES
# ==========================================================

@app.context_processor
def global_template_variables():

    return {

        "app_name": (
            "AI Phishing Email Detector"
        ),

        "current_year": datetime.utcnow().year

    }


# ==========================================================
# CREATE DATABASE TABLES
# ==========================================================

def initialize_application():

    try:

        with app.app_context():

            db.create_all()

            print(
                "Database initialized successfully."
            )

    except Exception as error:

        print(
            "Database Initialization Error:",
            error
        )


# ==========================================================
# INITIALIZE APPLICATION
# ==========================================================

initialize_application()


# ==========================================================
# RUN APPLICATION
# ==========================================================

if __name__ == "__main__":
    app.run(debug=True)

# ==========================================================
# END OF PART 2C
# END OF APP.PY
# ==========================================================