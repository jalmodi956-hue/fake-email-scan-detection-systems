from flask import Flask, render_template, request
from difflib import SequenceMatcher
from flask import send_file
from reportlab.pdfgen import canvas
import os
import re
import sqlite3
import csv
from datetime import datetime

app = Flask(__name__)

DATABASE = "database.db"

def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT,
        domain TEXT,
        risk_score INTEGER,
        verdict TEXT,
        scan_time TEXT
    )
    """)

    conn.commit()
    conn.close()

init_db()

# Trusted domains file path
trusted_domains_file = os.path.join(os.path.dirname(__file__), "trusted_domains.txt")

# Check if file exists
if not os.path.exists(trusted_domains_file):
    raise FileNotFoundError(f"trusted_domains.txt not found: {trusted_domains_file}")

# Load trusted domains
with open(trusted_domains_file, "r", encoding="utf-8") as file:
    trusted_domains = [line.strip().lower() for line in file if line.strip()]

print("Trusted Domains Loaded:")
print(trusted_domains)


@app.route("/", methods=["GET", "POST"])
def home():
    result = ""
    email = ""
    domain = ""
    content = ""
    risk_score = 0
    verdict = ""
    
    if request.method == "POST":
        scan_time = datetime.now().strftime("%d-%m-%y%H:%M:%S")
        email = request.form.get("email", "").strip().lower()
        content = request.form.get("content", "").lower()
        urls=re.findall(r'https?://[^\s]+',content)

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
            "otp"
        ]

        found_keywords = []

        for word in keywords:
            if word in content:
                found_keywords.append(word)

        # Email validation
        if "@" not in email or email.startswith("@") or email.endswith("@"):
            result = "❌ Invalid Email Address"

        else:
            domain = email.split("@", 1)[1].strip()

            print("Email:", email)
            print("Domain:", domain)

            if domain in trusted_domains:
                result = f"✅ SAFE DOMAIN : {domain}"
                risk_score += 0
            else:
                similar_domain = None

                for trusted in trusted_domains:
                    similarity = SequenceMatcher(None, domain, trusted).ratio()

                    if similarity >= 0.80:
                        similar_domain = trusted
                        break

                if similar_domain:
                    risk_score += 30
                    result = (
                        f"⚠️ SUSPICIOUS DOMAIN : {domain}<br>"
                        f"Looks Similar To : {similar_domain}"
                    )
                else:
                    risk_score += 40
                    result = f"❌ UNKNOWN DOMAIN : {domain}"

        if found_keywords:
            risk_score += len(found_keywords) * 10
            result += "<br><br>⚠️ Suspicious Keywords Found:<br>"
            result += ", ".join(found_keywords)
        else:
            result += "<br><br>✅ No Suspicious Keywords Found"

        if urls:
            risk_score += 20
            result +="<br><br><b>URL Detected:</b><br>"

            for url in urls:
                result += f"{url}<br>"
        
            result +="<br> suspicious URL found"
        else:
            result +="<br><br> No URL found"

        if risk_score <= 30:
            verdict ="safe"
        elif risk_score <= 60:
            verdict ="suspicious"
        else:
            verdict ="phishing"

        result += f"<br><br><hr>"
        result += f"<br><br><b>risk score:</b> {risk_score}%"
        result += f"<br><b>verdict:</b>{verdict}"
        result += f"<br><b>Scan Time:</b> {scan_time}"

        print("FINAL RESULT:")
        print(result)
        print("risk :",risk_score)
        print("verdict :",verdict)
        print("scan Time:",scan_time)

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        cursor.execute("""INSERT INTO scans (email, domain, risk_score, verdict, scan_time)
VALUES (?, ?, ?, ?, ?)""", 
(email, domain, risk_score, verdict, scan_time))

        conn.commit()
        conn.close()
    
    return render_template("index.html", result=result,email=email,content=content,verdict=verdict,risk_score=risk_score)

@app.route("/dashboard")
def dashboard():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Total Emails
    cursor.execute("SELECT COUNT(*) FROM scans")
    total = cursor.fetchone()[0]

    # Safe Emails
    cursor.execute("SELECT COUNT(*) FROM scans WHERE verdict='safe'")
    safe = cursor.fetchone()[0]

    # Suspicious Emails
    cursor.execute("SELECT COUNT(*) FROM scans WHERE verdict='suspicious'")
    suspicious = cursor.fetchone()[0]

    # Phishing Emails
    cursor.execute("SELECT COUNT(*) FROM scans WHERE verdict='phishing'")
    phishing = cursor.fetchone()[0]

    # Last 10 Scans
    cursor.execute("""
        SELECT email, domain, risk_score, verdict, scan_time
        FROM scans
        ORDER BY id DESC
        LIMIT 10
    """)

    history = cursor.fetchall()

    conn.close()

    return render_template(
        "dashboard.html",
        total=total,
        safe=safe,
        suspicious=suspicious,
        phishing=phishing,
        history=history
    )
@app.route("/export")
def export_csv():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("SELECT email, domain, risk_score, verdict, scan_time FROM scans")
    rows = cursor.fetchall()

    conn.close()

    with open("scan_history.csv", "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)

        writer.writerow(["Email", "Domain", "Risk Score", "Verdict", "Scan Time"])

        for row in rows:
            writer.writerow(row)

    return "CSV Exported Successfully!"

@app.route("/pdf")
def download_pdf():

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT email, domain, risk_score, verdict, scan_time
        FROM scans
        ORDER BY id DESC
        LIMIT 1
    """)

    row = cursor.fetchone()
    conn.close()

    if row is None:
        return "No Scan Data Found!"

    pdf_file = "Email_Report.pdf"

    c = canvas.Canvas(pdf_file)

    c.setFont("Helvetica-Bold", 18)
    c.drawString(150, 800, "Fake Email Scan Report")

    c.setFont("Helvetica", 12)
    c.drawString(50, 750, f"Email : {row[0]}")
    c.drawString(50, 720, f"Domain : {row[1]}")
    c.drawString(50, 690, f"Risk Score : {row[2]}%")
    c.drawString(50, 660, f"Verdict : {row[3]}")
    c.drawString(50, 630, f"Scan Time : {row[4]}")

    c.save()

    return send_file(pdf_file, as_attachment=True)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)