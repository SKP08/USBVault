# 🔐 USB Vault Project

USB Vault is a secure USB-based encrypted vault system designed for cybersecurity
and digital forensics learning. It uses strong cryptography, PIN authentication,
Two-Factor Authentication (TOTP), and encrypted forensic logging.

---

## 🚀 Key Features
- USB-based encrypted vault
- AES-256 (AES-GCM) encryption
- PBKDF2 key derivation (200,000 iterations)
- PIN-based authentication
- Google Authenticator (TOTP) for PIN reset
- Encrypted forensic activity logs
- GUI application using PySide6
- Deleted file archive with 30-day auto cleanup
- Optional Telegram security alerts

---

## 📁 Project Files
encrypt.py → Create vault and setup 2FA 
launcher.py → CLI-based vault access
app_launcher.py → GUI vault manager (Main file)
log_manager.py → Encrypted forensic logging
view_logs.py → Standalone log viewer


---

## ⚙️ Requirements
- Python 3.9 or higher
- Windows OS
- Blank USB drive

---

## 🛠 Installation
```bash
git clone https://github.com/<your-username>/USBVault.git
cd USBVault
pip install -r requirements.txt


--- 


🔌 Usage
1️⃣ Create Vault (Run once)
python encrypt.py


Enter USB drive letter

Set PIN

Scan QR using Google Authenticator

2️⃣ Open Vault (CLI)
python launcher.py

3️⃣ Open Vault (GUI)
python app_launcher.py

4️⃣ View Logs (CLI)
python view_logs.py

🔔 Telegram Alerts (Optional)

To enable Telegram alerts, set environment variables:

TELEGRAM_BOT_TOKEN
TELEGRAM_CHAT_ID

⚠️ Security Notice

This project is intended for educational and research purposes only.
Do not use on systems without proper authorization.


---

