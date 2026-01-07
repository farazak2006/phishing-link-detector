# 🔐 Phishing Link Detection System

This project is a web-based application that helps identify whether a given URL is **potentially phishing or safe**.  
It is built using **Python and Flask** and follows basic cybersecurity detection principles.

The system does **not guarantee 100% accuracy**, but it demonstrates how phishing detection works in real-world security tools.

---

## 🎯 Project Objective

The main goal of this project is to:
- Understand common phishing techniques
- Analyze suspicious URLs using multiple checks
- Demonstrate how cybersecurity tools classify links based on risk

This project is developed **for educational and academic purposes**.

---

## ⚙️ How the Project Works (Simple Explanation)

When a user enters a URL, the system performs **multiple checks**:

### 1️⃣ URL Pattern Analysis  
The URL is checked for suspicious patterns such as:
- Fake login words (`login`, `verify`, `secure`)
- Random numbers
- Unusual symbols

These are common indicators used in phishing links.

---

### 2️⃣ HTTPS Verification  
- Secure websites usually use **HTTPS**
- Links without HTTPS are considered **more risky**

---

### 3️⃣ Domain Existence Check  
- The system checks whether the domain actually exists
- Non-existing or unreachable domains increase risk

---

### 4️⃣ VirusTotal Reputation Check (Optional but Recommended)  
If a **VirusTotal API key** is added:
- The URL is checked against multiple security engines
- If the link is reported as malicious or suspicious, the risk score increases

This improves accuracy significantly.

---

### 5️⃣ Risk Scoring & Final Verdict  
Based on all checks:
- A **risk score** is calculated
- A final verdict is shown:
  - High Risk – Likely Phishing
  - Suspicious Link
  - No known phishing indicators found

The reasons for the verdict are also displayed for transparency.

---

## 🖥️ User Interface

- Clean and professional design
- Dark cybersecurity-themed background
- Clear result explanation
- Easy to use form-based input

---

## 🛠️ Technology Stack

- Python 3
- Flask (Web Framework)
- HTML & CSS
- VirusTotal API (Threat Intelligence)
- Git & GitHub

---

## 🚀 How to Run the Project Locally

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/farazak2006/phishing-link-detector.git
cd phishing-link-detector

