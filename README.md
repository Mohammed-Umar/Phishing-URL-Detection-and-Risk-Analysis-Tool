# 🛡️ Phishing URL Detector & Risk Analysis Tool

A modern, Python-based application that analyzes URLs to determine whether they are **Safe**, **Suspicious**, or **Dangerous** by checking various phishing indicators. It provides a real-time risk score, detailed explanations, and visual feedback.

---

## 🎯 **Core Features**

- **URL Input System**:
  - Manual entry with **real-time debouncing** (analyzes while you type).
  - **QR Code Scanner**: Extract URLs from images or your webcam.
- **Phishing Detection Engine**:
  - Checks for **URL length**, **special symbols** (@, -, //), and **IP address usage**.
  - Identifies **suspicious keywords** (login, bank, secure, verify, etc.).
- **Risk Scoring System**:
  - Score from **0 to 100**.
  - Classification into **Safe** (Green), **Suspicious** (Yellow), and **Dangerous** (Red).
- **Explainable Analysis**:
  - Displays exactly why a URL is flagged.
  - **Typosquatting Detection**: Detects similar domains (e.g., `goggle.com` vs `google.com`).
- **URL History Tracker**: Stores previously checked URLs for quick access.
- **Modern GUI**: A stylish, dark-themed interface built with `CustomTkinter`.

---

## 🧠 **How It Works (Logic)**

The tool uses a **Rule-Based Detection Engine** to analyze the URL's structure and content:

1.  **Feature Extraction**: Breaks down the URL into scheme, domain, path, and subdomains.
2.  **Scoring Algorithm**:
    - **IP Address**: High penalty (e.g., `http://192.168.1.1`).
    - **At Symbol (@)**: High penalty (used to hide domains).
    - **Excessive Dots/Subdomains**: Penalty for mimicking legitimate brands.
    - **No HTTPS**: Penalty for insecure sites.
    - **Keyword Matching**: Searches for deceptive terms like `paypal`, `invoice`, `update`.
3.  **Typosquatting Check**: Compares the domain against a list of the top 100+ popular domains using `difflib` similarity.

---

## 🏗️ **Technology Stack**

- **Language**: Python 3
- **GUI**: [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter)
- **Scanning**: [OpenCV](https://opencv.org/) (Computer Vision for QR)
- **Networking**: `requests`, `tldextract`
- **Threading**: Ensures smooth UI performance during analysis.

---

## 🚀 **Getting Started**

### **1. Prerequisites**
Ensure you have Python 3 installed. You can install the required dependencies using:

```bash
pip install customtkinter pillow opencv-python tldextract
```

### **2. Running the Application**
Clone the repository and run:

```bash
python3 app.py
```

---

## 📸 **Screenshots / Examples**

| Result Level | Score | Description |
| :--- | :--- | :--- |
| **🟢 Safe** | 0 - 30 | Legitimate domains like `google.com`. |
| **🟡 Suspicious** | 31 - 70 | Typo-squatted domains or missing HTTPS. |
| **🔴 Dangerous** | 71 - 100 | IP-based URLs with multiple phishing keywords. |

---

## 🧪 **Verification**
You can run a validation test of the detection logic by executing:

```bash
python3 tests/verify_logic.py
```

---

## 📝 **Project Information**
- **Developed for**: College Mini-Project
- **Author**: Mohammed Umar
- **License**: MIT
