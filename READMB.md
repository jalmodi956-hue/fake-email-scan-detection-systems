# 📧 Fake Email Detector

A Flask-based cybersecurity project that detects suspicious or phishing emails using **rule-based analysis** and **AI-powered analysis**.

## 🚀 Features

* Email address and email content scanning
* Trusted domain checking
* Suspicious keyword detection
* URL detection
* Risk score calculation
* Final verdict:

  * **Safe**
  * **Suspicious**
  * **Phishing**
* AI analysis using Anthropic API
* Scan history saved in SQLite database
* Dashboard with scan statistics
* Export scan history to CSV
* Download latest scan report as PDF

---

## 🛠️ Tech Stack

* **Python**
* **Flask**
* **SQLite**
* **Bootstrap**
* **ReportLab**
* **Anthropic API**

---

## 📂 Project Structure

```bash
Fake_Email_Detector/
│── app.py
│── requirements.txt
│── trusted_domains.txt
│── .gitignore
│── database.db
│── scan_history.csv
│── Email_Report.pdf
│
├── templates/
│   ├── index.html
│   └── dashboard.html
```

---

## ⚙️ Installation

### 1) Clone the repository

```bash
git clone <your-repo-link>
cd Fake_Email_Detector
```

### 2) Install dependencies

```bash
pip install -r requirements.txt
```

### 3) Add trusted domains

Create a file named **trusted_domains.txt** and add trusted domains like:

```txt
gmail.com
google.com
yahoo.com
outlook.com
hotmail.com
paypal.com
amazon.com
github.com
```

### 4) Set Anthropic API key

For **PowerShell**:

```powershell
$env:ANTHROPIC_API_KEY="your_api_key_here"
```

---

## ▶️ Run the Project

```bash
python app.py
```

Then open in browser:

```bash
http://127.0.0.1:5000
```

---

## 📊 Dashboard

The dashboard shows:

* Total scans
* Safe emails count
* Suspicious emails count
* Phishing emails count
* Recent scan history

---

## 📁 Export Features

* **Export CSV** → Download scan history
* **Download PDF** → Download latest email scan report

---

## 🧪 Sample Test Email

### Email:

```text
security@paypa1.com
```

### Content:

```text
URGENT!

Your PayPal account has been suspended.
Click here immediately to verify your password and OTP:
http://fake-paypal-login.com

Failure to act now may result in permanent account suspension.
```

Expected result:

* **High Risk Score**
* **Phishing Verdict**

---

## 📌 Notes

* If Anthropic API is not configured, the app still works using **rule-based analysis**.
* AI analysis requires:

  * `anthropic` package installed
  * valid `ANTHROPIC_API_KEY`

---

## 👨‍💻 Author

**Jal Modi**
