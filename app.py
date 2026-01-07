from flask import Flask, render_template, request
import re
import socket
import requests
import base64
from urllib.parse import urlparse

app = Flask(__name__)

# ---------------- Helper functions ----------------

def is_suspicious_url(url):
    patterns = [r"@", r"-login", r"-secure", r"-verify", r"\d{3,}"]
    return any(re.search(p, url) for p in patterns)

def domain_exists(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except:
        return False

VT_API_KEY = "PASTE_YOUR_API_KEY_HERE"


def check_virustotal(url):
    try:
        encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VT_API_KEY}

        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{encoded_url}",
            headers=headers,
            timeout=10
        )

        if response.status_code != 200:
            return None

        stats = response.json()["data"]["attributes"]["last_analysis_stats"]
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0)
        }
    except:
        return None

# ---------------- Main route ----------------

@app.route("/", methods=["GET", "POST"])
def index():
    result = None

    if request.method == "POST":
        url = request.form["url"].strip()

        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        domain = urlparse(url).netloc

        risk = 0
        reasons = []

        if is_suspicious_url(url):
            risk += 20
            reasons.append("Suspicious URL pattern")

        if not domain_exists(domain):
            risk += 30
            reasons.append("Domain does not resolve")

        if not url.startswith("https://"):
            risk += 10
            reasons.append("No HTTPS connection")

        vt_result = check_virustotal(url)
        if vt_result:
            if vt_result["malicious"] > 0:
                risk += 50
                reasons.append("Flagged malicious by VirusTotal")
            elif vt_result["suspicious"] > 0:
                risk += 30
                reasons.append("Flagged suspicious by VirusTotal")

        if risk >= 70:
            verdict = "⚠️ High Risk – Likely Phishing"
        elif risk >= 40:
            verdict = "⚠️ Suspicious Link"
        else:
            verdict = "✅ No known phishing indicators found"

        result = {
            "url": url,
            "risk": risk,
            "verdict": verdict,
            "reasons": reasons
        }

    return render_template("index.html", result=result)

# ---------------- Run app ----------------

if __name__ == "__main__":
    app.run(debug=True)
