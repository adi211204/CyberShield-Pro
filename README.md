# CyberShield-Pro 🛡️
**Advanced Forensic Triage & Malware Static Analysis Platform**

CyberShield-Pro is a professional-grade security dashboard designed for rapid file analysis. It helps security researchers identify malicious payloads by combining signature-based detection with heuristic analysis.

## 🚀 Technical Features
* **YARA Signature Matching:** Integrates an industrial-standard YARA engine to detect known malware families.
* **Shannon Entropy Analysis:** Calculates data randomness to identify packed, compressed, or encrypted code (common in ransomware).
* **SHA-256 Fingerprinting:** Generates unique cryptographic hashes for file integrity and database lookups.
* **Role-Based Data Isolation:** Secure user authentication system where forensic history is isolated per user.
* **Modern Security UI:** Sleek, dark-mode dashboard built with Bootstrap for a professional researcher experience.

## 🛠️ Tech Stack
- **Backend:** Python (Flask)
- **Database:** SQLAlchemy / SQLite
- **Security Logic:** YARA, Hashlib, Bcrypt
- **Frontend:** Bootstrap 5, Jinja2

## 📋 How to Use
1. **Register/Login:** Create a secure researcher account.
2. **Upload:** Drag and drop any suspicious file into the audit engine.
3. **Analyze:** Review the Risk Score, Entropy, and YARA match results.
4. **History:** Track your previous scans in the persistent forensic log.

## ⚠️ Disclaimer
This tool is for **educational and ethical security research purposes only**. Never analyze files without explicit permission.
