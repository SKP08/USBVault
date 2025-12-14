import sys
import os
import subprocess
import multiprocessing
import json
import getpass
import shutil
from pathlib import Path


# ==================== PATH RESOLUTION FOR PYINSTALLER ====================
def get_base_dir():
    """
    Get the base directory - works for both PyCharm and PyInstaller exe.
    When running as exe on USB, returns the directory where exe is located.
    """
    if getattr(sys, 'frozen', False):
        # Running as PyInstaller executable
        base_dir = os.path.dirname(sys.executable)
    else:
        # Running as script in PyCharm
        base_dir = os.path.dirname(os.path.abspath(__file__))
    return base_dir


BASE_DIR = get_base_dir()

# ==================== Add base directory to sys.path ====================
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# ==================== PySide6 Imports ====================
from PySide6.QtWidgets import (QApplication, QWidget, QPushButton,
                               QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
                               QSpacerItem, QSizePolicy, QStackedWidget, QTextEdit,
                               QFormLayout, QScrollArea, QMessageBox)
from PySide6.QtCore import (Qt, QPoint, QThread, QObject, Signal, Slot,
                            QPropertyAnimation, QEasingCurve, QRect, QTimer)
from PySide6.QtGui import QColor, QPainter, QFont


# ==================== TELEGRAM NOTIFICATION ====================
def send_telegram_notification(message):
    """Send notification to Telegram"""
    try:
        import requests
        import socket
        import getpass as gp
        from datetime import datetime

        import sys
        import os
        import subprocess
        import multiprocessing
        import json
        import getpass
        import shutil
        from pathlib import Path

        # ==================== PATH RESOLUTION FOR PYINSTALLER ====================
        def get_base_dir():
            """
            Get the base directory - works for both PyCharm and PyInstaller exe.
            When running as exe on USB, returns the directory where exe is located.
            """
            if getattr(sys, 'frozen', False):
                # Running as PyInstaller executable
                base_dir = os.path.dirname(sys.executable)
            else:
                # Running as script in PyCharm
                base_dir = os.path.dirname(os.path.abspath(__file__))
            return base_dir

        BASE_DIR = get_base_dir()

        # ==================== Add base directory to sys.path ====================
        if BASE_DIR not in sys.path:
            sys.path.insert(0, BASE_DIR)

        # ==================== PySide6 Imports ====================
        from PySide6.QtWidgets import (QApplication, QWidget, QPushButton,
                                       QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
                                       QSpacerItem, QSizePolicy, QStackedWidget, QTextEdit,
                                       QFormLayout, QScrollArea, QMessageBox)
        from PySide6.QtCore import (Qt, QPoint, QThread, QObject, Signal, Slot,
                                    QPropertyAnimation, QEasingCurve, QRect, QTimer)
        from PySide6.QtGui import QColor, QPainter, QFont

        # ==================== TELEGRAM NOTIFICATION ====================
        def send_telegram_notification(message):
            """Send notification to Telegram"""
            try:
                import requests
                import socket
                import getpass as gp
                from datetime import datetime

                # Your Telegram credentials
                bot_token = os.getenv("TELEGRAM_BOT_TOKEN")
                chat_id = os.getenv("TELEGRAM_CHAT_ID")

                # Get system info for notification
                try:
                    pc_name = socket.gethostname()
                except:
                    pc_name = "Unknown"

                try:
                    username = gp.getuser()
                except:
                    username = "Unknown"

                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                # Format message
                notification_text = f"""
        🔐 *USB Vault Alert*

        {message}

        📅 Time: {timestamp}
        💻 PC: {pc_name}
        👤 User: {username}
        """

                # Send to Telegram
                url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
                data = {
                    "chat_id": chat_id,
                    "text": notification_text,
                    "parse_mode": "Markdown"
                }

                response = requests.post(url, data=data, timeout=5)

                if response.status_code == 200:
                    print(f"[Telegram] ✅ Notification sent: {message}")
                else:
                    print(f"[Telegram] ❌ Failed to send: {response.text}")

            except Exception as e:
                print(f"[Telegram] Error: {e}")
                # Don't fail vault operations if notification fails

        # ==================== EMBEDDED: log_manager.py (FIXED VERSION) ====================
        def append_log(usb_path, key, event):
            """Log manager functionality - embedded in exe - FIXED VERSION"""
            try:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                from datetime import datetime
                import secrets
                import socket
                import uuid
                import platform
                import getpass as gp

                # Try to import psutil, but don't fail if not available
                try:
                    import psutil
                    has_psutil = True
                except ImportError:
                    has_psutil = False
                    print("[Warning] psutil not installed - RAM info will show as Unknown")

                # ✅ FIXED: Use correct path
                log_file = os.path.join(usb_path, ".dll", "logs.enc")

                # ✅ FIXED: Get system info with better error handling
                def get_cpu_model():
                    try:
                        if platform.system().lower() == "windows":
                            output = subprocess.check_output(
                                "wmic cpu get Name",
                                shell=True,
                                stderr=subprocess.DEVNULL,
                                timeout=5
                            ).decode(errors="ignore").strip().split("\n")
                            if len(output) > 1 and output[1].strip():
                                return output[1].strip()
                    except Exception as e:
                        print(f"[CPU Detection] Windows method failed: {e}")

                    try:
                        if os.path.exists("/proc/cpuinfo"):
                            with open("/proc/cpuinfo", "r") as f:
                                for line in f:
                                    if "model name" in line:
                                        return line.split(":", 1)[1].strip()
                    except Exception as e:
                        print(f"[CPU Detection] Linux method failed: {e}")

                    try:
                        proc = platform.processor()
                        if proc:
                            return proc
                    except Exception as e:
                        print(f"[CPU Detection] Platform method failed: {e}")

                    return "Unknown"

                def get_system_info():
                    info = {}

                    # PC Name
                    try:
                        info["pc_name"] = socket.gethostname()
                    except Exception as e:
                        print(f"[System Info] Hostname failed: {e}")
                        info["pc_name"] = "Unknown"

                    # Username
                    try:
                        info["username"] = gp.getuser()
                    except Exception as e:
                        print(f"[System Info] Username failed: {e}")
                        info["username"] = "Unknown"

                    # MAC Address
                    try:
                        mac = uuid.getnode()
                        info["mac"] = ":".join(f"{(mac >> ele) & 0xff:02x}" for ele in range(40, -1, -8))
                    except Exception as e:
                        print(f"[System Info] MAC failed: {e}")
                        info["mac"] = "Unknown"

                    # OS Name
                    try:
                        info["os_name"] = platform.system()
                    except Exception as e:
                        print(f"[System Info] OS name failed: {e}")
                        info["os_name"] = "Unknown"

                    # OS Version
                    try:
                        info["os_version"] = platform.release()
                    except Exception as e:
                        print(f"[System Info] OS version failed: {e}")
                        info["os_version"] = "Unknown"

                    # CPU
                    try:
                        info["cpu"] = get_cpu_model()
                    except Exception as e:
                        print(f"[System Info] CPU failed: {e}")
                        info["cpu"] = "Unknown"

                    # RAM
                    try:
                        if has_psutil:
                            ram = round(psutil.virtual_memory().total / (1024 ** 3), 2)
                            info["ram_gb"] = ram
                        else:
                            info["ram_gb"] = "Unknown"
                    except Exception as e:
                        print(f"[System Info] RAM failed: {e}")
                        info["ram_gb"] = "Unknown"

                    return info

                # Load existing logs
                logs = []
                if os.path.exists(log_file):
                    try:
                        with open(log_file, "rb") as f:
                            encrypted_logs = f.read()
                        if len(encrypted_logs) > 12:
                            nonce = encrypted_logs[:12]
                            ciphertext = encrypted_logs[12:]
                            aesgcm = AESGCM(key)
                            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
                            logs = json.loads(plaintext.decode())
                    except Exception as e:
                        print(f"[Log Loading] Failed to load existing logs: {e}")
                        logs = []

                # Create proper log entry with full system info
                try:
                    info = get_system_info()
                    logs.append({
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "event": event,
                        "pc_name": info.get("pc_name", "Unknown"),
                        "username": info.get("username", "Unknown"),
                        "mac": info.get("mac", "Unknown"),
                        "os_name": info.get("os_name", "Unknown"),
                        "os_version": info.get("os_version", "Unknown"),
                        "cpu": info.get("cpu", "Unknown"),
                        "ram_gb": info.get("ram_gb", "Unknown")
                    })
                except Exception as e:
                    print(f"[Log Entry Creation] Failed: {e}")
                    # Fallback: create minimal log entry
                    logs.append({
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "event": event,
                        "pc_name": "Unknown",
                        "username": "Unknown",
                        "mac": "Unknown",
                        "os_name": "Unknown",
                        "os_version": "Unknown",
                        "cpu": "Unknown",
                        "ram_gb": "Unknown"
                    })

                # Encrypt and save
                try:
                    nonce = secrets.token_bytes(12)
                    aesgcm = AESGCM(key)
                    ciphertext = aesgcm.encrypt(nonce, json.dumps(logs).encode(), None)

                    with open(log_file, "wb") as f:
                        f.write(nonce + ciphertext)

                    print(f"[Log] Successfully logged: {event}")

                except Exception as e:
                    print(f"[Log Saving] Failed to save log: {e}")
                    import traceback
                    traceback.print_exc()

            except Exception as e:
                print(f"[Log Manager Error]: {e}")
                import traceback
                traceback.print_exc()

        # ==================== TOTP HELPER FUNCTIONS ====================
        def load_totp_secret(usb_path, key):
            """Load and decrypt TOTP secret"""
            try:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM

                totp_file = os.path.join(usb_path, ".dll", "totp.enc")

                if not os.path.exists(totp_file):
                    return None

                with open(totp_file, "rb") as f:
                    data = f.read()

                if len(data) < 12:
                    return None

                nonce = data[:12]
                ciphertext = data[12:]

                aesgcm = AESGCM(key)
                plaintext = aesgcm.decrypt(nonce, ciphertext, None)
                return plaintext.decode()

            except Exception as e:
                print(f"Error loading TOTP: {e}")
                return None

        def verify_totp(secret, otp):
            """Verify TOTP code"""
            try:
                import pyotp
                totp = pyotp.TOTP(secret)
                return totp.verify(otp, valid_window=1)  # Allow 30s window
            except:
                return False

        def update_pin_in_meta(usb_path, old_key, new_pin):
            """Update PIN in metadata file and re-encrypt everything"""
            try:
                import secrets
                from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM

                meta_path = os.path.join(usb_path, ".dll", "meta.key")

                # Load old metadata
                with open(meta_path, "rb") as f:
                    content = f.read()

                salt = content[:16]  # Keep same salt

                # Derive new key from new PIN
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=200000
                )
                new_key = kdf.derive(new_pin.encode())

                # Generate new nonce
                new_nonce = secrets.token_bytes(12)

                # Re-encrypt vault with new key
                vault_path = os.path.join(usb_path, ".dll", "vault.enc")
                with open(vault_path, "rb") as f:
                    old_vault_data = f.read()

                # Decrypt with old key
                old_meta_nonce = content[16:28]
                aesgcm_old = AESGCM(old_key)
                vault_plaintext = aesgcm_old.decrypt(old_meta_nonce, old_vault_data, None)

                # Re-encrypt with new key
                aesgcm_new = AESGCM(new_key)
                new_vault_ciphertext = aesgcm_new.encrypt(new_nonce, vault_plaintext, None)

                # Write new vault
                with open(vault_path, "wb") as f:
                    f.write(new_vault_ciphertext)

                # Write new metadata
                new_meta = salt + new_nonce + bytes([len(new_pin)]) + new_pin.encode()
                with open(meta_path, "wb") as f:
                    f.write(new_meta)

                # Re-encrypt TOTP secret with new key
                totp_secret = load_totp_secret(usb_path, old_key)
                if totp_secret:
                    totp_nonce = secrets.token_bytes(12)
                    totp_ciphertext = aesgcm_new.encrypt(totp_nonce, totp_secret.encode(), None)
                    totp_path = os.path.join(usb_path, ".dll", "totp.enc")
                    with open(totp_path, "wb") as f:
                        f.write(totp_nonce + totp_ciphertext)

                return True

            except Exception as e:
                print(f"Error updating PIN: {e}")
                import traceback
                traceback.print_exc()
                return False

        # ==================== EMBEDDED: launcher.py functionality ====================
        class VaultManager:
            """All launcher.py functionality embedded here"""

            USB_ROOT = None
            VAULT_DIR_NAME = ".dll"
            META_FILE = "meta.key"
            VAULT_FILE = "vault.enc"
            TEMP_VAULT = r"C:\USBVaultTemp"

            @staticmethod
            def detect_usb():
                """Detect USB drive with vault"""
                for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                    check_path = f"{letter}:\\{VaultManager.VAULT_DIR_NAME}\\{VaultManager.META_FILE}"
                    if os.path.exists(check_path):
                        return letter + ":"
                return None

            @staticmethod
            def load_meta(usb_path):
                """Load metadata from vault"""
                path = os.path.join(usb_path, VaultManager.VAULT_DIR_NAME, VaultManager.META_FILE)
                with open(path, "rb") as f:
                    content = f.read()

                salt = content[:16]
                nonce = content[16:28]
                pin_len = content[28]
                pin = content[29:29 + pin_len].decode()

                return salt, nonce, pin

            @staticmethod
            def derive_key(pin, salt):
                """Derive encryption key from PIN"""
                from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
                from cryptography.hazmat.primitives import hashes

                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=200000
                )
                return kdf.derive(pin.encode())

            @staticmethod
            def decrypt_vault(usb_path, key):
                """Decrypt vault"""
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM

                vault_path = os.path.join(usb_path, VaultManager.VAULT_DIR_NAME, VaultManager.VAULT_FILE)
                meta_path = os.path.join(usb_path, VaultManager.VAULT_DIR_NAME, VaultManager.META_FILE)

                with open(vault_path, "rb") as f:
                    ct = f.read()
                with open(meta_path, "rb") as f:
                    meta = f.read()

                nonce = meta[16:28]

                aesgcm = AESGCM(key)
                plaintext = aesgcm.decrypt(nonce, ct, None)
                return json.loads(plaintext.decode())

            @staticmethod
            def encrypt_vault(usb_path, key, data):
                """Re-encrypt vault"""
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                import secrets

                aesgcm = AESGCM(key)
                nonce = secrets.token_bytes(12)

                ct = aesgcm.encrypt(nonce, json.dumps(data).encode(), None)

                vault_path = os.path.join(usb_path, VaultManager.VAULT_DIR_NAME, VaultManager.VAULT_FILE)
                meta_path = os.path.join(usb_path, VaultManager.VAULT_DIR_NAME, VaultManager.META_FILE)

                with open(vault_path, "wb") as f:
                    f.write(ct)

                # Keep same salt + PIN, replace nonce
                with open(meta_path, "rb") as f:
                    content = f.read()

                salt = content[:16]
                pin_len = content[28]
                pin = content[29:29 + pin_len]

                new_meta = salt + nonce + bytes([pin_len]) + pin

                with open(meta_path, "wb") as f:
                    f.write(new_meta)

        # ==================== LOG VIEWER FUNCTIONALITY ====================
        class LogViewerManager(QObject):
            """Handles log loading and decryption"""
            logs_loaded = Signal(list)
            error_occurred = Signal(str)

            def __init__(self, usb_path, key):
                super().__init__()
                self.usb_path = usb_path
                self.key = key

            def load_logs(self):
                """Load and decrypt logs"""
                try:
                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

                    log_file = os.path.join(self.usb_path, ".dll", "logs.enc")

                    if not os.path.exists(log_file):
                        self.logs_loaded.emit([])
                        return

                    with open(log_file, "rb") as f:
                        data = f.read()

                    if len(data) < 12:
                        self.logs_loaded.emit([])
                        return

                    nonce = data[:12]
                    ciphertext = data[12:]

                    aesgcm = AESGCM(self.key)
                    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
                    logs = json.loads(plaintext.decode())

                    # Reverse for newest first
                    self.logs_loaded.emit(list(reversed(logs)))

                except Exception as e:
                    self.error_occurred.emit(f"Failed to load logs: {str(e)}")

        # ==================== ARCHIVE MANAGER ====================
        class ArchiveManager:
            """Manages archived (deleted) files with 30-day retention"""

            ARCHIVE_FILE = "archive.enc"
            RETENTION_DAYS = 30

            def __init__(self, usb_path, key):
                self.usb_path = usb_path
                self.key = key
                self.archive_path = os.path.join(usb_path, ".dll", self.ARCHIVE_FILE)

            def load_archive(self):
                """Load and decrypt archive"""
                try:
                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

                    if not os.path.exists(self.archive_path):
                        return {"archived_files": []}

                    with open(self.archive_path, "rb") as f:
                        data = f.read()

                    if len(data) < 12:
                        return {"archived_files": []}

                    nonce = data[:12]
                    ciphertext = data[12:]

                    aesgcm = AESGCM(self.key)
                    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
                    return json.loads(plaintext.decode())

                except Exception as e:
                    print(f"[Archive] Error loading archive: {e}")
                    return {"archived_files": []}

            def save_archive(self, archive_data):
                """Encrypt and save archive"""
                try:
                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                    import secrets

                    nonce = secrets.token_bytes(12)
                    aesgcm = AESGCM(self.key)
                    ciphertext = aesgcm.encrypt(nonce, json.dumps(archive_data).encode(), None)

                    with open(self.archive_path, "wb") as f:
                        f.write(nonce + ciphertext)

                    return True
                except Exception as e:
                    print(f"[Archive] Error saving archive: {e}")
                    return False

            def archive_file(self, filename, original_path, content):
                """Archive a deleted file"""
                try:
                    from datetime import datetime
                    import uuid

                    archive_data = self.load_archive()

                    # Calculate file size
                    file_size = len(content)
                    if file_size < 1024:
                        size_readable = f"{file_size} B"
                    elif file_size < 1024 * 1024:
                        size_readable = f"{file_size / 1024:.1f} KB"
                    else:
                        size_readable = f"{file_size / (1024 * 1024):.1f} MB"

                    # Create archive entry
                    now = datetime.now()
                    entry = {
                        "id": str(uuid.uuid4()),
                        "filename": filename,
                        "original_path": original_path,
                        "deleted_date": now.strftime("%Y-%m-%d"),
                        "deleted_time": now.strftime("%H:%M:%S"),
                        "deleted_timestamp": now.timestamp(),
                        "file_size_bytes": file_size,
                        "file_size_readable": size_readable,
                        "content": list(content)
                    }

                    archive_data["archived_files"].append(entry)
                    return self.save_archive(archive_data)

                except Exception as e:
                    print(f"[Archive] Error archiving file: {e}")
                    return False

            def cleanup_old_files(self):
                """Delete files older than 30 days"""
                try:
                    from datetime import datetime, timedelta

                    archive_data = self.load_archive()
                    cutoff_timestamp = (datetime.now() - timedelta(days=self.RETENTION_DAYS)).timestamp()

                    original_count = len(archive_data["archived_files"])

                    # Filter out old files
                    archive_data["archived_files"] = [
                        f for f in archive_data["archived_files"]
                        if f.get("deleted_timestamp", 0) > cutoff_timestamp
                    ]

                    deleted_count = original_count - len(archive_data["archived_files"])

                    if deleted_count > 0:
                        self.save_archive(archive_data)
                        print(f"[Archive] Auto-deleted {deleted_count} files older than {self.RETENTION_DAYS} days")
                        return deleted_count

                    return 0

                except Exception as e:
                    print(f"[Archive] Error cleaning up old files: {e}")
                    return 0

            def get_files_grouped_by_month(self):
                """Get archived files grouped by month/year"""
                try:
                    from datetime import datetime
                    from collections import defaultdict

                    archive_data = self.load_archive()
                    grouped = defaultdict(list)

                    for file_entry in archive_data["archived_files"]:
                        try:
                            date_str = file_entry.get("deleted_date", "")
                            date_obj = datetime.strptime(date_str, "%Y-%m-%d")
                            month_key = date_obj.strftime("%B %Y")  # e.g., "November 2025"

                            # Calculate days remaining
                            deleted_timestamp = file_entry.get("deleted_timestamp", 0)
                            now_timestamp = datetime.now().timestamp()
                            days_old = int((now_timestamp - deleted_timestamp) / 86400)
                            days_remaining = self.RETENTION_DAYS - days_old

                            file_entry["days_remaining"] = max(0, days_remaining)
                            grouped[month_key].append(file_entry)
                        except:
                            continue

                    # Sort months (newest first)
                    sorted_groups = []
                    for month_key in sorted(grouped.keys(), reverse=True,
                                            key=lambda x: datetime.strptime(x, "%B %Y")):
                        sorted_groups.append({
                            "month": month_key,
                            "files": sorted(grouped[month_key],
                                            key=lambda x: x.get("deleted_timestamp", 0),
                                            reverse=True)
                        })

                    return sorted_groups

                except Exception as e:
                    print(f"[Archive] Error grouping files: {e}")
                    return []

            def restore_file(self, file_id):
                """Restore file from archive back to vault"""
                try:
                    archive_data = self.load_archive()

                    # Find file by ID
                    file_to_restore = None
                    for i, f in enumerate(archive_data["archived_files"]):
                        if f.get("id") == file_id:
                            file_to_restore = archive_data["archived_files"].pop(i)
                            break

                    if not file_to_restore:
                        return None, "File not found in archive"

                    # Save updated archive
                    self.save_archive(archive_data)

                    # Return file data for adding back to vault
                    return {
                        "path": file_to_restore.get("original_path"),
                        "content": bytes(file_to_restore.get("content", []))
                    }, None

                except Exception as e:
                    print(f"[Archive] Error restoring file: {e}")
                    return None, str(e)

            def delete_permanently(self, file_id):
                """Permanently delete file from archive"""
                try:
                    archive_data = self.load_archive()

                    # Remove file by ID
                    original_count = len(archive_data["archived_files"])
                    archive_data["archived_files"] = [
                        f for f in archive_data["archived_files"]
                        if f.get("id") != file_id
                    ]

                    if len(archive_data["archived_files"]) < original_count:
                        self.save_archive(archive_data)
                        return True

                    return False

                except Exception as e:
                    print(f"[Archive] Error deleting file: {e}")
                    return False

            def get_statistics(self):
                """Get archive statistics"""
                try:
                    archive_data = self.load_archive()
                    files = archive_data["archived_files"]

                    if not files:
                        return {
                            "total_files": 0,
                            "total_size_bytes": 0,
                            "total_size_readable": "0 B"
                        }

                    total_size = sum(f.get("file_size_bytes", 0) for f in files)

                    if total_size < 1024:
                        size_readable = f"{total_size} B"
                    elif total_size < 1024 * 1024:
                        size_readable = f"{total_size / 1024:.1f} KB"
                    else:
                        size_readable = f"{total_size / (1024 * 1024):.1f} MB"

                    return {
                        "total_files": len(files),
                        "total_size_bytes": total_size,
                        "total_size_readable": size_readable
                    }

                except Exception as e:
                    print(f"[Archive] Error getting statistics: {e}")
                    return {"total_files": 0, "total_size_bytes": 0, "total_size_readable": "0 B"}

        # ==================== 🎨 Premium Palette ====================
        GLASS_COLOR = QColor(255, 255, 255, 180)
        ACCENT_COLOR = "#007AFF"
        TEXT_COLOR = "#222222"
        ERROR_COLOR = "#D93025"
        SUCCESS_COLOR = "#4CAF50"
        WARNING_COLOR = "#FF9800"

        CLOSE_BTN_BG = "rgba(255, 255, 255, 40)"
        CLOSE_BTN_HOVER = "rgba(255, 255, 255, 80)"
        CLOSE_BTN_PRESSED = "rgba(255, 0, 0, 60)"

        # ==================== WORKER THREAD (Vault Process Manager) ====================
        class VaultProcessManager(QObject):
            status_updated = Signal(str)
            usb_detected = Signal(str)
            pin_verified = Signal()
            pin_incorrect = Signal()
            vault_mounted = Signal(str)
            vault_locked = Signal()

            def __init__(self):
                super().__init__()
                self.vault_manager = VaultManager()
                self.usb_root = None
                self.key = None
                self.user_pin = None
                self.vault_data = None

            def run(self):
                """Start the vault detection process."""
                try:
                    print("Detecting secure USB...")
                    self.status_updated.emit("Detecting secure USB...")

                    # Detect USB
                    self.usb_root = self.vault_manager.detect_usb()
                    if self.usb_root is None:
                        self.status_updated.emit("❌ Secure USB not detected. Please insert USB drive.")
                        print("❌ Secure USB not detected.")
                        return

                    print(f"✔ USB found at {self.usb_root}")
                    self.status_updated.emit(f"✔ USB found at {self.usb_root}")

                    # 📱 Send notification - USB plugged in
                    send_telegram_notification("⚠️ Someone plugged in the USB vault!")

                    self.usb_detected.emit(self.usb_root)

                except Exception as e:
                    error_msg = f"Error: {str(e)}"
                    self.status_updated.emit(error_msg)
                    print(f"[Error in VaultProcessManager]: {e}")
                    import traceback
                    traceback.print_exc()

            def verify_pin(self, user_pin):
                """Verify PIN"""
                try:
                    # Load metadata
                    salt, nonce, correct_pin = self.vault_manager.load_meta(self.usb_root)

                    if user_pin != correct_pin:
                        self.status_updated.emit("Incorrect PIN")
                        self.pin_incorrect.emit()
                        print("❌ Incorrect PIN.")

                        # 📱 Send notification - Wrong PIN
                        send_telegram_notification(
                            "❌ *ALERT: Wrong PIN entered!*\nSomeone tried to access the vault with incorrect PIN.")

                        return

                    print("✔ PIN verified")
                    self.status_updated.emit("✔ PIN verified")

                    # Derive key and store
                    self.key = self.vault_manager.derive_key(user_pin, salt)
                    self.user_pin = user_pin

                    # 📱 Send notification - Correct PIN
                    send_telegram_notification("✅ *Vault Accessed Successfully*\nCorrect PIN was entered.")

                    self.pin_verified.emit()

                except Exception as e:
                    error_msg = f"Error: {str(e)}"
                    self.status_updated.emit(error_msg)
                    print(f"[Error verifying PIN]: {e}")
                    import traceback
                    traceback.print_exc()

            def mount_vault(self):
                """Mount and decrypt vault with auto-cleanup"""
                try:
                    if not self.usb_root or not self.key:
                        self.status_updated.emit("Error: Not authenticated")
                        return

                    print("Mounting vault...")
                    self.status_updated.emit("Mounting vault...")

                    # Auto-cleanup old archived files (30+ days)
                    try:
                        archive_manager = ArchiveManager(self.usb_root, self.key)
                        deleted_count = archive_manager.cleanup_old_files()
                        if deleted_count > 0:
                            append_log(self.usb_root, self.key,
                                       f"Auto-deleted {deleted_count} archived files (30+ days old)")
                    except Exception as e:
                        print(f"[Archive] Cleanup failed: {e}")

                    # Create temp folder
                    if os.path.exists(self.vault_manager.TEMP_VAULT):
                        shutil.rmtree(self.vault_manager.TEMP_VAULT)
                    os.makedirs(self.vault_manager.TEMP_VAULT, exist_ok=True)

                    # Decrypt vault
                    self.vault_data = self.vault_manager.decrypt_vault(self.usb_root, self.key)
                    print("✔ Vault decrypted")
                    self.status_updated.emit("✔ Vault decrypted")

                    # Log the event
                    append_log(self.usb_root, self.key, "Vault Opened")

                    # 📱 Send notification - Vault opened
                    send_telegram_notification("🔓 *Vault Opened*\nFiles are now accessible.")

                    # Extract decrypted files to TEMP
                    for name, content in self.vault_data["files"].items():
                        file_path = os.path.join(self.vault_manager.TEMP_VAULT, name)
                        os.makedirs(os.path.dirname(file_path), exist_ok=True)

                        with open(file_path, "wb") as f:
                            f.write(bytes(content))

                    print(f"Vault opened at: {self.vault_manager.TEMP_VAULT}")
                    self.vault_mounted.emit(self.vault_manager.TEMP_VAULT)

                except Exception as e:
                    error_msg = f"Error: {str(e)}"
                    self.status_updated.emit(error_msg)
                    print(f"[Error mounting vault]: {e}")
                    import traceback
                    traceback.print_exc()

            def lock_vault(self):
                """Re-encrypt and lock the vault with archive support"""
                try:
                    if not self.usb_root or not self.key:
                        self.status_updated.emit("Error: Vault not unlocked")
                        return

                    print("Rebuilding vault...")
                    self.status_updated.emit("Rebuilding vault...")

                    # Get old vault data (what was there before)
                    old_vault_data = self.vault_data if self.vault_data else {"files": {}}

                    # Rebuild vault from temp files (current state)
                    new_data = {"files": {}}

                    for root, dirs, files in os.walk(self.vault_manager.TEMP_VAULT):
                        for file in files:
                            p = os.path.join(root, file)
                            rel_path = os.path.relpath(p, self.vault_manager.TEMP_VAULT)

                            with open(p, "rb") as f:
                                new_data["files"][rel_path] = list(f.read())

                    # Detect deleted files (existed before but not now)
                    deleted_files = []
                    for old_path in old_vault_data.get("files", {}).keys():
                        if old_path not in new_data["files"]:
                            deleted_files.append(old_path)

                    # Archive deleted files
                    if deleted_files:
                        print(f"[Archive] Detected {len(deleted_files)} deleted file(s)")
                        archive_manager = ArchiveManager(self.usb_root, self.key)

                        for file_path in deleted_files:
                            try:
                                filename = os.path.basename(file_path)
                                content = bytes(old_vault_data["files"][file_path])

                                success = archive_manager.archive_file(filename, file_path, content)
                                if success:
                                    print(f"[Archive] Archived: {filename}")
                                    append_log(self.usb_root, self.key, f"File Archived: {filename}")
                            except Exception as e:
                                print(f"[Archive] Failed to archive {file_path}: {e}")

                    # Re-encrypt vault
                    self.vault_manager.encrypt_vault(self.usb_root, self.key, new_data)
                    print("✔ Vault re-encrypted")
                    self.status_updated.emit("✔ Vault re-encrypted")

                    # Clean up temp folder
                    shutil.rmtree(self.vault_manager.TEMP_VAULT)
                    print("✔ Temp folder removed")

                    # Log the event
                    append_log(self.usb_root, self.key, "Vault Closed")

                    # 📱 Send notification - Vault closed
                    send_telegram_notification("🔒 *Vault Locked*\nVault has been secured.")

                    self.vault_locked.emit()

                except Exception as e:
                    error_msg = f"Error: {str(e)}"
                    self.status_updated.emit(error_msg)
                    print(f"[Error locking vault]: {e}")
                    import traceback
                    traceback.print_exc()

            def stop(self):
                """Clean up resources."""
                try:
                    if os.path.exists(self.vault_manager.TEMP_VAULT):
                        shutil.rmtree(self.vault_manager.TEMP_VAULT)
                except Exception as e:
                    print(f"Error cleaning up: {e}")

        # ==================== MAIN GUI APPLICATION ====================
        class GlassWindow(QWidget):

            def __init__(self):
                super().__init__()
                self.setWindowTitle("USB Vault")
                self.resize(600, 520)
                self.setWindowFlags(Qt.FramelessWindowHint)
                self.setAttribute(Qt.WA_TranslucentBackground)

                self.drag_pos = None
                self.temp_path = ""
                self.usb_root = None
                self.vault_key = None

                # Screen state tracking
                self.current_screen = "DETECTING"

                # Create widgets and animations
                self.create_widgets()
                self.create_animations()
                self.add_close_button()

                # Setup backend thread
                self.setup_backend_thread()

            def create_widgets(self):
                """Create all GUI widgets with multi-screen support."""
                self.main_layout = QVBoxLayout(self)
                self.main_layout.setContentsMargins(40, 50, 40, 50)
                self.main_layout.setSpacing(5)

                # Stacked widget for multiple screens
                self.stacked_widget = QStackedWidget(self)
                self.stacked_widget.setStyleSheet("background: transparent;")

                # Create screens
                self.screen_detecting = self.create_detecting_screen()
                self.screen_pin_entry = self.create_pin_entry_screen()
                self.screen_main_menu = self.create_main_menu_screen()
                self.screen_vault_open = self.create_vault_open_screen()
                self.screen_log_viewer = self.create_log_viewer_screen()
                self.screen_pin_reset = self.create_pin_reset_screen()
                self.screen_archive = self.create_archive_screen()

                # Add screens to stack
                self.stacked_widget.addWidget(self.screen_detecting)  # Index 0
                self.stacked_widget.addWidget(self.screen_pin_entry)  # Index 1
                self.stacked_widget.addWidget(self.screen_main_menu)  # Index 2
                self.stacked_widget.addWidget(self.screen_vault_open)  # Index 3
                self.stacked_widget.addWidget(self.screen_log_viewer)  # Index 4
                self.stacked_widget.addWidget(self.screen_pin_reset)  # Index 5
                self.stacked_widget.addWidget(self.screen_archive)  # Index 6

                self.main_layout.addWidget(self.stacked_widget)

                # Start on detecting screen
                self.stacked_widget.setCurrentIndex(0)

            def create_detecting_screen(self):
                """Screen 0: USB Detection"""
                widget = QWidget()
                layout = QVBoxLayout(widget)
                layout.setAlignment(Qt.AlignCenter)
                layout.setSpacing(20)

                title = QLabel("🔍 Detecting USB Vault")
                title.setFont(QFont("Arial", 24, QFont.Weight.Bold))
                title.setStyleSheet(f"color: {TEXT_COLOR}; background: transparent;")
                title.setAlignment(Qt.AlignCenter)

                status = QLabel("Please insert your USB vault...")
                status.setFont(QFont("Arial", 12))
                status.setStyleSheet(f"color: {TEXT_COLOR}; background: transparent;")
                status.setAlignment(Qt.AlignCenter)

                layout.addStretch()
                layout.addWidget(title)
                layout.addWidget(status)
                layout.addStretch()

                self.detecting_status = status
                return widget

            def create_pin_entry_screen(self):
                """Screen 1: PIN Entry"""
                widget = QWidget()
                layout = QVBoxLayout(widget)
                layout.setAlignment(Qt.AlignCenter)
                layout.setSpacing(20)

                title = QLabel("🔐 Enter PIN")
                title.setFont(QFont("Arial", 24, QFont.Weight.Bold))
                title.setStyleSheet(f"color: {TEXT_COLOR}; background: transparent;")
                title.setAlignment(Qt.AlignCenter)

                status = QLabel("Vault detected. Please enter your PIN.")
                status.setFont(QFont("Arial", 12))
                status.setStyleSheet(f"color: {TEXT_COLOR}; background: transparent;")
                status.setWordWrap(True)
                status.setAlignment(Qt.AlignCenter)

                # PIN Input
                pin_input = QLineEdit()
                pin_input.setEchoMode(QLineEdit.Password)
                pin_input.setPlaceholderText("Enter PIN")
                pin_input.setFixedSize(220, 50)
                pin_input.setAlignment(Qt.AlignCenter)
                pin_input.setFont(QFont("Arial", 14))
                pin_input.returnPressed.connect(self.verify_pin)
                pin_input.setStyleSheet(f"""
                    QLineEdit {{
                        background-color: rgba(0, 0, 0, 0.05);
                        border: 2px solid rgba(0, 0, 0, 0.1);
                        border-radius: 25px; padding: 0 15px; color: {TEXT_COLOR};
                    }}
                    QLineEdit:focus {{ border: 2px solid {ACCENT_COLOR}; }}
                """)

                # Unlock Button
                unlock_btn = QPushButton("Unlock")
                unlock_btn.setFixedSize(200, 55)
                unlock_btn.setFont(QFont("Arial", 16, QFont.Weight.DemiBold))
                unlock_btn.clicked.connect(self.verify_pin)
                unlock_btn.setStyleSheet(f"""
                    QPushButton {{
                        background-color: {ACCENT_COLOR};
                        color: white; border: none; border-radius: 27px;
                    }}
                    QPushButton:hover {{ background-color: #0070e6; }}
                    QPushButton:pressed {{ background-color: #0062cc; }}
                """)

                layout.addStretch()
                layout.addWidget(title)
                layout.addWidget(status)
                layout.addWidget(pin_input, alignment=Qt.AlignCenter)
                layout.addWidget(unlock_btn, alignment=Qt.AlignCenter)
                layout.addStretch()

                self.pin_input = pin_input
                self.pin_status = status
                return widget

            def create_main_menu_screen(self):
                """Screen 2: Main Menu (after PIN verified)"""
                widget = QWidget()
                layout = QVBoxLayout(widget)
                layout.setAlignment(Qt.AlignCenter)
                layout.setSpacing(15)

                title = QLabel("✅ Authenticated")
                title.setFont(QFont("Arial", 24, QFont.Weight.Bold))
                title.setStyleSheet(f"color: {TEXT_COLOR}; background: transparent;")
                title.setAlignment(Qt.AlignCenter)

                subtitle = QLabel("Choose an action:")
                subtitle.setFont(QFont("Arial", 13))
                subtitle.setStyleSheet(f"color: {TEXT_COLOR}; background: transparent;")
                subtitle.setAlignment(Qt.AlignCenter)

                # Open Vault Button
                btn_open_vault = QPushButton("🔓 Open Vault")
                btn_open_vault.setFixedSize(280, 55)
                btn_open_vault.setFont(QFont("Arial", 14, QFont.Weight.DemiBold))
                btn_open_vault.clicked.connect(self.open_vault_action)
                btn_open_vault.setStyleSheet(f"""
                    QPushButton {{
                        background-color: {ACCENT_COLOR};
                        color: white; border: none; border-radius: 27px;
                    }}
                    QPushButton:hover {{ background-color: #0070e6; }}
                """)

                # View Logs Button
                btn_view_logs = QPushButton("📋 View Logs")
                btn_view_logs.setFixedSize(280, 55)
                btn_view_logs.setFont(QFont("Arial", 14, QFont.Weight.DemiBold))
                btn_view_logs.clicked.connect(self.view_logs_action)
                btn_view_logs.setStyleSheet(f"""
                    QPushButton {{
                        background-color: rgba(0, 122, 255, 0.15);
                        color: {ACCENT_COLOR}; border: 2px solid {ACCENT_COLOR};
                        border-radius: 27px;
                    }}
                    QPushButton:hover {{ background-color: rgba(0, 122, 255, 0.25); }}
                """)

                # Archive Button
                btn_archive = QPushButton("📦 Deleted Files")
                btn_archive.setFixedSize(280, 55)
                btn_archive.setFont(QFont("Arial", 14, QFont.Weight.DemiBold))
                btn_archive.clicked.connect(self.view_archive_action)
                btn_archive.setStyleSheet(f"""
                    QPushButton {{
                        background-color: rgba(156, 39, 176, 0.15);
                        color: #9C27B0; border: 2px solid #9C27B0;
                        border-radius: 27px;
                    }}
                    QPushButton:hover {{ background-color: rgba(156, 39, 176, 0.25); }}
                """)

                # PIN Reset Button
                btn_reset_pin = QPushButton("🔑 Reset PIN")
                btn_reset_pin.setFixedSize(280, 55)
                btn_reset_pin.setFont(QFont("Arial", 14, QFont.Weight.DemiBold))
                btn_reset_pin.clicked.connect(self.reset_pin_action)
                btn_reset_pin.setStyleSheet(f"""
                    QPushButton {{
                        background-color: rgba(255, 152, 0, 0.15);
                        color: {WARNING_COLOR}; border: 2px solid {WARNING_COLOR};
                        border-radius: 27px;
                    }}
                    QPushButton:hover {{ background-color: rgba(255, 152, 0, 0.25); }}
                """)

                layout.addStretch()
                layout.addWidget(title)
                layout.addWidget(subtitle)
                layout.addSpacing(15)
                layout.addWidget(btn_open_vault, alignment=Qt.AlignCenter)
                layout.addWidget(btn_view_logs, alignment=Qt.AlignCenter)
                layout.addWidget(btn_archive, alignment=Qt.AlignCenter)
                layout.addWidget(btn_reset_pin, alignment=Qt.AlignCenter)
                layout.addStretch()

                return widget

            def create_vault_open_screen(self):
                """Screen 3: Vault Open"""
                widget = QWidget()
                layout = QVBoxLayout(widget)
                layout.setAlignment(Qt.AlignCenter)
                layout.setSpacing(20)

                title = QLabel("🔓 Vault Open")
                title.setFont(QFont("Arial", 24, QFont.Weight.Bold))
                title.setStyleSheet(f"color: {TEXT_COLOR}; background: transparent;")
                title.setAlignment(Qt.AlignCenter)

                status = QLabel("Your vault is accessible.\nEdit files, then lock when done.")
                status.setFont(QFont("Arial", 12))
                status.setStyleSheet(f"color: {TEXT_COLOR}; background: transparent;")
                status.setWordWrap(True)
                status.setAlignment(Qt.AlignCenter)

                # Open Folder Button
                btn_open_folder = QPushButton("📁 Open Folder")
                btn_open_folder.setFixedSize(250, 55)
                btn_open_folder.setFont(QFont("Arial", 14, QFont.Weight.DemiBold))
                btn_open_folder.clicked.connect(self.open_vault_folder)
                btn_open_folder.setStyleSheet(f"""
                    QPushButton {{
                        background-color: rgba(0, 122, 255, 0.1);
                        color: {ACCENT_COLOR}; border: 2px solid {ACCENT_COLOR};
                        border-radius: 27px;
                    }}
                    QPushButton:hover {{ background-color: rgba(0, 122, 255, 0.2); }}
                """)

                # Lock Vault Button
                btn_lock_vault = QPushButton("🔒 Lock Vault")
                btn_lock_vault.setFixedSize(250, 55)
                btn_lock_vault.setFont(QFont("Arial", 14, QFont.Weight.DemiBold))
                btn_lock_vault.clicked.connect(self.lock_vault_action)
                btn_lock_vault.setStyleSheet(f"""
                    QPushButton {{
                        background-color: {ACCENT_COLOR};
                        color: white; border: none; border-radius: 27px;
                    }}
                    QPushButton:hover {{ background-color: #0070e6; }}
                """)

                # Back to Menu Button
                btn_back = QPushButton("← Back to Menu")
                btn_back.setFixedSize(180, 45)
                btn_back.setFont(QFont("Arial", 12))
                btn_back.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(2))
                btn_back.setStyleSheet(f"""
                    QPushButton {{
                        background-color: transparent;
                        color: {TEXT_COLOR}; border: 1px solid rgba(0,0,0,0.2);
                        border-radius: 22px;
                    }}
                    QPushButton:hover {{ background-color: rgba(0,0,0,0.05); }}
                """)

                layout.addStretch()
                layout.addWidget(title)
                layout.addWidget(status)
                layout.addSpacing(15)
                layout.addWidget(btn_open_folder, alignment=Qt.AlignCenter)
                layout.addWidget(btn_lock_vault, alignment=Qt.AlignCenter)
                layout.addSpacing(10)
                layout.addWidget(btn_back, alignment=Qt.AlignCenter)
                layout.addStretch()

                return widget

            def create_log_viewer_screen(self):
                """Screen 4: Log Viewer"""
                widget = QWidget()
                layout = QVBoxLayout(widget)
                layout.setContentsMargins(30, 30, 30, 30)
                layout.setSpacing(15)

                # Header
                header = QWidget()
                header_layout = QHBoxLayout(header)
                header_layout.setContentsMargins(0, 0, 0, 0)

                title = QLabel("📋 Forensic Logs")
                title.setFont(QFont("Arial", 20, QFont.Weight.Bold))
                title.setStyleSheet(f"color: {TEXT_COLOR}; background: transparent;")

                btn_back = QPushButton("← Back")
                btn_back.setFixedSize(100, 35)
                btn_back.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(2))
                btn_back.setStyleSheet(f"""
                    QPushButton {{
                        background-color: rgba(0,0,0,0.05);
                        border: 1px solid rgba(0,0,0,0.1);
                        border-radius: 17px; color: {TEXT_COLOR};
                    }}
                    QPushButton:hover {{ background-color: rgba(0,0,0,0.1); }}
                """)

                header_layout.addWidget(title)
                header_layout.addStretch()
                header_layout.addWidget(btn_back)

                # Log display area
                log_display = QTextEdit()
                log_display.setReadOnly(True)
                log_display.setStyleSheet(f"""
                    QTextEdit {{
                        background-color: rgba(0, 0, 0, 0.03);
                        border: 1px solid rgba(0, 0, 0, 0.1);
                        border-radius: 12px;
                        padding: 15px;
                        color: {TEXT_COLOR};
                        font-family: 'Courier New', monospace;
                        font-size: 11px;
                    }}
                """)

                layout.addWidget(header)
                layout.addWidget(log_display)

                self.log_display = log_display
                return widget

            def create_pin_reset_screen(self):
                """Screen 5: PIN Reset with 2FA"""
                widget = QWidget()
                layout = QVBoxLayout(widget)
                layout.setAlignment(Qt.AlignCenter)
                layout.setSpacing(15)
                layout.setContentsMargins(40, 30, 40, 30)

                title = QLabel("🔑 Reset PIN")
                title.setFont(QFont("Arial", 22, QFont.Weight.Bold))
                title.setStyleSheet(f"color: {TEXT_COLOR}; background: transparent;")
                title.setAlignment(Qt.AlignCenter)

                subtitle = QLabel("Verify your identity with current PIN and 2FA code")
                subtitle.setFont(QFont("Arial", 11))
                subtitle.setStyleSheet(f"color: {TEXT_COLOR}; background: transparent;")
                subtitle.setWordWrap(True)
                subtitle.setAlignment(Qt.AlignCenter)

                # Form container
                form_widget = QWidget()
                form_widget.setMaximumWidth(400)
                form_layout = QFormLayout(form_widget)
                form_layout.setSpacing(12)
                form_layout.setLabelAlignment(Qt.AlignRight)

                input_style = f"""
                    QLineEdit {{
                        background-color: rgba(0, 0, 0, 0.05);
                        border: 2px solid rgba(0, 0, 0, 0.1);
                        border-radius: 8px; padding: 0 12px; color: {TEXT_COLOR};
                        font-size: 13px;
                    }}
                    QLineEdit:focus {{ border: 2px solid {ACCENT_COLOR}; }}
                """

                # Current PIN
                current_pin_input = QLineEdit()
                current_pin_input.setEchoMode(QLineEdit.Password)
                current_pin_input.setPlaceholderText("Current PIN")
                current_pin_input.setFixedHeight(45)
                current_pin_input.setStyleSheet(input_style)

                # TOTP Code
                totp_input = QLineEdit()
                totp_input.setPlaceholderText("6-digit code")
                totp_input.setFixedHeight(45)
                totp_input.setMaxLength(6)
                totp_input.setStyleSheet(input_style)

                # Hint label for TOTP
                totp_hint = QLabel("Open Google Authenticator app")
                totp_hint.setFont(QFont("Arial", 9))
                totp_hint.setStyleSheet(f"color: rgba(34, 34, 34, 0.6); background: transparent;")

                # New PIN
                new_pin_input = QLineEdit()
                new_pin_input.setEchoMode(QLineEdit.Password)
                new_pin_input.setPlaceholderText("New PIN")
                new_pin_input.setFixedHeight(45)
                new_pin_input.setStyleSheet(input_style)

                # Confirm New PIN
                confirm_pin_input = QLineEdit()
                confirm_pin_input.setEchoMode(QLineEdit.Password)
                confirm_pin_input.setPlaceholderText("Confirm New PIN")
                confirm_pin_input.setFixedHeight(45)
                confirm_pin_input.setStyleSheet(input_style)

                # Add fields to form
                form_layout.addRow("Current PIN:", current_pin_input)
                form_layout.addRow("2FA Code:", totp_input)
                form_layout.addRow("", totp_hint)
                form_layout.addRow("New PIN:", new_pin_input)
                form_layout.addRow("Confirm:", confirm_pin_input)

                # Status label
                status_label = QLabel("")
                status_label.setFont(QFont("Arial", 11))
                status_label.setStyleSheet(f"color: {TEXT_COLOR}; background: transparent;")
                status_label.setAlignment(Qt.AlignCenter)
                status_label.setWordWrap(True)
                status_label.setMinimumHeight(40)

                # Buttons
                button_container = QWidget()
                button_layout = QHBoxLayout(button_container)
                button_layout.setSpacing(10)

                btn_cancel = QPushButton("Cancel")
                btn_cancel.setFixedSize(120, 45)
                btn_cancel.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(2))
                btn_cancel.setStyleSheet(f"""
                    QPushButton {{
                        background-color: rgba(0,0,0,0.05);
                        border: 1px solid rgba(0,0,0,0.2);
                        border-radius: 22px; color: {TEXT_COLOR};
                        font-size: 13px;
                    }}
                    QPushButton:hover {{ background-color: rgba(0,0,0,0.1); }}
                """)

                btn_reset = QPushButton("Reset PIN")
                btn_reset.setFixedSize(140, 45)
                btn_reset.clicked.connect(self.process_pin_reset)
                btn_reset.setStyleSheet(f"""
                    QPushButton {{
                        background-color: {ACCENT_COLOR};
                        color: white; border: none; border-radius: 22px;
                        font-size: 13px; font-weight: bold;
                    }}
                    QPushButton:hover {{ background-color: #0070e6; }}
                """)

                button_layout.addWidget(btn_cancel)
                button_layout.addWidget(btn_reset)

                layout.addStretch()
                layout.addWidget(title)
                layout.addWidget(subtitle)
                layout.addSpacing(10)
                layout.addWidget(form_widget, alignment=Qt.AlignCenter)
                layout.addWidget(status_label)
                layout.addWidget(button_container, alignment=Qt.AlignCenter)
                layout.addStretch()

                # Store references
                self.reset_current_pin = current_pin_input
                self.reset_totp = totp_input
                self.reset_new_pin = new_pin_input
                self.reset_confirm_pin = confirm_pin_input
                self.reset_status = status_label

                return widget

            def create_archive_screen(self):
                """Screen 6: Archive (Deleted Files) Viewer"""
                widget = QWidget()
                layout = QVBoxLayout(widget)
                layout.setContentsMargins(30, 30, 30, 30)
                layout.setSpacing(15)

                # Header
                header = QWidget()
                header_layout = QHBoxLayout(header)
                header_layout.setContentsMargins(0, 0, 0, 0)

                title = QLabel("📦 Deleted Files Archive")
                title.setFont(QFont("Arial", 20, QFont.Weight.Bold))
                title.setStyleSheet(f"color: {TEXT_COLOR}; background: transparent;")

                # Stats label
                stats_label = QLabel("Loading...")
                stats_label.setFont(QFont("Arial", 10))
                stats_label.setStyleSheet(f"color: {TEXT_COLOR}; background: transparent;")

                btn_back = QPushButton("← Back")
                btn_back.setFixedSize(100, 35)
                btn_back.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(2))
                btn_back.setStyleSheet(f"""
                    QPushButton {{
                        background-color: rgba(0,0,0,0.05);
                        border: 1px solid rgba(0,0,0,0.1);
                        border-radius: 17px; color: {TEXT_COLOR};
                    }}
                    QPushButton:hover {{ background-color: rgba(0,0,0,0.1); }}
                """)

                header_layout.addWidget(title)
                header_layout.addWidget(stats_label)
                header_layout.addStretch()
                header_layout.addWidget(btn_back)

                # Scroll area for files
                scroll_area = QScrollArea()
                scroll_area.setWidgetResizable(True)
                scroll_area.setStyleSheet("""
                    QScrollArea {
                        border: none;
                        background: transparent;
                    }
                """)

                # Container for file cards
                files_container = QWidget()
                files_layout = QVBoxLayout(files_container)
                files_layout.setSpacing(10)
                files_layout.setAlignment(Qt.AlignTop)

                scroll_area.setWidget(files_container)

                layout.addWidget(header)
                layout.addWidget(scroll_area)

                self.archive_stats_label = stats_label
                self.archive_files_container = files_container
                self.archive_files_layout = files_layout

                return widget

            def create_animations(self):
                """Create shake animation for incorrect PIN."""
                self.shake_animation = QPropertyAnimation(self.pin_input, b"geometry")
                self.shake_animation.setDuration(500)
                self.shake_animation.setEasingCurve(QEasingCurve.Type.InOutBounce)

                def update_shake_keyframes():
                    pos = self.pin_input.geometry()
                    self.shake_animation.setKeyValueAt(0.0, QRect(pos.x() - 10, pos.y(), pos.width(), pos.height()))
                    self.shake_animation.setKeyValueAt(0.1, QRect(pos.x() + 10, pos.y(), pos.width(), pos.height()))
                    self.shake_animation.setKeyValueAt(0.2, QRect(pos.x() - 10, pos.y(), pos.width(), pos.height()))
                    self.shake_animation.setKeyValueAt(0.3, QRect(pos.x() + 10, pos.y(), pos.width(), pos.height()))
                    self.shake_animation.setKeyValueAt(0.4, QRect(pos.x() - 10, pos.y(), pos.width(), pos.height()))
                    self.shake_animation.setKeyValueAt(0.5, QRect(pos.x() + 10, pos.y(), pos.width(), pos.height()))
                    self.shake_animation.setKeyValueAt(0.6, QRect(pos.x() - 10, pos.y(), pos.width(), pos.height()))
                    self.shake_animation.setKeyValueAt(0.7, QRect(pos.x() + 10, pos.y(), pos.width(), pos.height()))
                    self.shake_animation.setKeyValueAt(0.8, QRect(pos.x() - 10, pos.y(), pos.width(), pos.height()))
                    self.shake_animation.setKeyValueAt(0.9, QRect(pos.x() + 10, pos.y(), pos.width(), pos.height()))
                    self.shake_animation.setKeyValueAt(1.0, QRect(pos.x(), pos.y(), pos.width(), pos.height()))

                self.update_shake_keyframes = update_shake_keyframes

            def add_close_button(self):
                """Add close button to window"""
                self.close_btn = QPushButton("✕", self)
                self.close_btn.resize(28, 28)
                self.close_btn.move(self.width() - self.close_btn.width() - 15, 15)
                self.close_btn.clicked.connect(self.close)
                self.close_btn.setStyleSheet(f"""
                    QPushButton {{
                        background-color: {CLOSE_BTN_BG};
                        border-radius: 14px; 
                        border: none; color: {TEXT_COLOR};
                        font-size: 14px; font-weight: bold; padding-bottom: 1px;
                    }}
                    QPushButton:hover {{ background-color: {CLOSE_BTN_HOVER}; }}
                    QPushButton:pressed {{ background-color: {CLOSE_BTN_PRESSED}; }}
                """)
                self.close_btn.raise_()

            def setup_backend_thread(self):
                """Setup the worker thread for vault operations."""
                self.thread = QThread()
                self.manager = VaultProcessManager()
                self.manager.moveToThread(self.thread)

                # Connect signals
                self.manager.status_updated.connect(self.on_status_update)
                self.manager.usb_detected.connect(self.on_usb_detected)
                self.manager.pin_verified.connect(self.on_pin_verified)
                self.manager.pin_incorrect.connect(self.on_pin_incorrect)
                self.manager.vault_mounted.connect(self.on_vault_mounted)
                self.manager.vault_locked.connect(self.on_vault_locked)

                self.thread.started.connect(self.manager.run)
                self.thread.start()

            # ==================== ACTION HANDLERS ====================

            @Slot()
            def verify_pin(self):
                """Verify PIN and proceed to main menu"""
                pin = self.pin_input.text()
                if not pin:
                    return

                self.pin_status.setText("Verifying PIN...")
                self.pin_status.setStyleSheet(f"color: {TEXT_COLOR}; background: transparent;")
                self.pin_input.setEnabled(False)

                # Verify PIN in manager
                self.manager.verify_pin(pin)

            @Slot()
            def open_vault_action(self):
                """Open vault and mount files"""
                self.manager.mount_vault()

            @Slot()
            def view_logs_action(self):
                """Load and display logs"""
                self.log_display.setText("Loading logs...")
                self.stacked_widget.setCurrentIndex(4)  # Go to log viewer screen

                # Load logs
                log_viewer = LogViewerManager(self.manager.usb_root, self.manager.key)
                log_viewer.logs_loaded.connect(self.display_logs)
                log_viewer.error_occurred.connect(self.on_logs_error)
                log_viewer.load_logs()

            @Slot()
            def lock_vault_action(self):
                """Lock vault and return to menu"""
                self.manager.lock_vault()

            @Slot()
            def reset_pin_action(self):
                """Show PIN reset screen"""
                self.stacked_widget.setCurrentIndex(5)  # Go to PIN reset screen
                self.reset_status.setText("")
                self.reset_status.setStyleSheet(f"color: {TEXT_COLOR}; background: transparent;")
                self.reset_current_pin.clear()
                self.reset_totp.clear()
                self.reset_new_pin.clear()
                self.reset_confirm_pin.clear()
                self.reset_current_pin.setFocus()

            @Slot()
            def process_pin_reset(self):
                """Process PIN reset with 2FA verification"""
                current_pin = self.reset_current_pin.text().strip()
                totp_code = self.reset_totp.text().strip()
                new_pin = self.reset_new_pin.text().strip()
                confirm_pin = self.reset_confirm_pin.text().strip()

                # Validation
                if not all([current_pin, totp_code, new_pin, confirm_pin]):
                    self.reset_status.setText("❌ All fields are required")
                    self.reset_status.setStyleSheet(f"color: {ERROR_COLOR}; background: transparent;")
                    return

                if len(totp_code) != 6 or not totp_code.isdigit():
                    self.reset_status.setText("❌ TOTP code must be 6 digits")
                    self.reset_status.setStyleSheet(f"color: {ERROR_COLOR}; background: transparent;")
                    return

                if new_pin != confirm_pin:
                    self.reset_status.setText("❌ New PINs don't match")
                    self.reset_status.setStyleSheet(f"color: {ERROR_COLOR}; background: transparent;")
                    return

                if len(new_pin) < 4:
                    self.reset_status.setText("❌ PIN must be at least 4 characters")
                    self.reset_status.setStyleSheet(f"color: {ERROR_COLOR}; background: transparent;")
                    return

                if current_pin == new_pin:
                    self.reset_status.setText("❌ New PIN must be different from current PIN")
                    self.reset_status.setStyleSheet(f"color: {ERROR_COLOR}; background: transparent;")
                    return

                self.reset_status.setText("⏳ Verifying...")
                self.reset_status.setStyleSheet(f"color: {TEXT_COLOR}; background: transparent;")

                # Verify current PIN
                salt, nonce, correct_pin = VaultManager.load_meta(self.manager.usb_root)
                if current_pin != correct_pin:
                    self.reset_status.setText("❌ Current PIN is incorrect")
                    self.reset_status.setStyleSheet(f"color: {ERROR_COLOR}; background: transparent;")
                    return

                # Load and verify TOTP
                totp_secret = load_totp_secret(self.manager.usb_root, self.manager.key)
                if not totp_secret:
                    self.reset_status.setText("❌ 2FA not setup for this vault")
                    self.reset_status.setStyleSheet(f"color: {ERROR_COLOR}; background: transparent;")
                    return

                if not verify_totp(totp_secret, totp_code):
                    self.reset_status.setText("❌ Invalid 2FA code")
                    self.reset_status.setStyleSheet(f"color: {ERROR_COLOR}; background: transparent;")
                    return

                # Update PIN
                self.reset_status.setText("⏳ Updating PIN and re-encrypting vault...")
                success = update_pin_in_meta(self.manager.usb_root, self.manager.key, new_pin)

                if success:
                    # Update manager's key to new key
                    new_key = VaultManager.derive_key(new_pin, salt)
                    self.manager.key = new_key
                    self.vault_key = new_key

                    # Log the event
                    append_log(self.manager.usb_root, new_key, "PIN Reset (2FA Verified)")

                    # 📱 Send notification - PIN reset
                    send_telegram_notification("🔑 *PIN Changed*\nVault PIN was reset using 2FA.")

                    self.reset_status.setText("✅ PIN updated successfully!")
                    self.reset_status.setStyleSheet(f"color: {SUCCESS_COLOR}; background: transparent;")

                    # Return to menu after 2 seconds
                    QTimer.singleShot(2000, lambda: self.stacked_widget.setCurrentIndex(2))
                else:
                    self.reset_status.setText("❌ Failed to update PIN")
                    self.reset_status.setStyleSheet(f"color: {ERROR_COLOR}; background: transparent;")

            @Slot()
            def view_archive_action(self):
                """Show archive screen with deleted files"""
                self.stacked_widget.setCurrentIndex(6)  # Go to archive screen
                self.load_archived_files()

            def load_archived_files(self):
                """Load and display archived files"""
                try:
                    # Clear existing file cards
                    while self.archive_files_layout.count():
                        child = self.archive_files_layout.takeAt(0)
                        if child.widget():
                            child.widget().deleteLater()

                    # Get archive manager
                    archive_manager = ArchiveManager(self.manager.usb_root, self.manager.key)

                    # Get statistics
                    stats = archive_manager.get_statistics()
                    self.archive_stats_label.setText(
                        f"{stats['total_files']} files  •  {stats['total_size_readable']}  •  Auto-delete after 30 days"
                    )

                    # Get files grouped by month
                    grouped_files = archive_manager.get_files_grouped_by_month()

                    if not grouped_files:
                        no_files_label = QLabel("No deleted files in archive.")
                        no_files_label.setAlignment(Qt.AlignCenter)
                        no_files_label.setStyleSheet(f"color: {TEXT_COLOR}; padding: 40px; font-size: 14px;")
                        self.archive_files_layout.addWidget(no_files_label)
                        return

                    # Display files grouped by month
                    for group in grouped_files:
                        # Month header
                        month_header = QLabel(f"📅 {group['month']}")
                        month_header.setFont(QFont("Arial", 14, QFont.Weight.Bold))
                        month_header.setStyleSheet(f"color: {TEXT_COLOR}; background: transparent; padding: 10px 0;")
                        self.archive_files_layout.addWidget(month_header)

                        # File cards
                        for file_entry in group['files']:
                            file_card = self.create_archive_file_card(file_entry)
                            self.archive_files_layout.addWidget(file_card)

                except Exception as e:
                    print(f"[Archive UI] Error loading files: {e}")
                    error_label = QLabel(f"Error loading archive: {str(e)}")
                    error_label.setStyleSheet(f"color: {ERROR_COLOR}; padding: 20px;")
                    self.archive_files_layout.addWidget(error_label)

            def create_archive_file_card(self, file_entry):
                """Create a card widget for an archived file"""
                card = QWidget()
                card.setStyleSheet(f"""
                    QWidget {{
                        background-color: rgba(0, 0, 0, 0.03);
                        border: 1px solid rgba(0, 0, 0, 0.1);
                        border-radius: 10px;
                        padding: 15px;
                    }}
                """)

                layout = QVBoxLayout(card)
                layout.setSpacing(8)

                # File info row
                info_row = QWidget()
                info_layout = QHBoxLayout(info_row)
                info_layout.setContentsMargins(0, 0, 0, 0)

                # File icon and name
                filename = file_entry.get("filename", "Unknown")
                ext = os.path.splitext(filename)[1].lower()

                if ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp']:
                    icon = "🖼️"
                elif ext in ['.pdf']:
                    icon = "📄"
                elif ext in ['.doc', '.docx']:
                    icon = "📝"
                elif ext in ['.xls', '.xlsx']:
                    icon = "📊"
                elif ext in ['.zip', '.rar', '.7z']:
                    icon = "📦"
                elif ext in ['.mp4', '.avi', '.mov']:
                    icon = "🎥"
                elif ext in ['.mp3', '.wav', '.flac']:
                    icon = "🎵"
                else:
                    icon = "📄"

                file_label = QLabel(f"{icon} {filename}")
                file_label.setFont(QFont("Arial", 13, QFont.Weight.DemiBold))
                file_label.setStyleSheet(f"color: {TEXT_COLOR}; background: transparent;")

                size_label = QLabel(file_entry.get("file_size_readable", ""))
                size_label.setFont(QFont("Arial", 11))
                size_label.setStyleSheet(f"color: rgba(34, 34, 34, 0.6); background: transparent;")

                info_layout.addWidget(file_label)
                info_layout.addStretch()
                info_layout.addWidget(size_label)

                # Details row
                deleted_date = file_entry.get("deleted_date", "")
                deleted_time = file_entry.get("deleted_time", "")
                days_remaining = file_entry.get("days_remaining", 30)
                original_path = file_entry.get("original_path", "")

                details_label = QLabel(
                    f"Deleted: {deleted_date} at {deleted_time}  •  "
                    f"Days remaining: {days_remaining}  •  "
                    f"Path: {original_path}"
                )
                details_label.setFont(QFont("Arial", 10))
                details_label.setStyleSheet(f"color: rgba(34, 34, 34, 0.5); background: transparent;")
                details_label.setWordWrap(True)

                # Buttons row
                buttons_row = QWidget()
                buttons_layout = QHBoxLayout(buttons_row)
                buttons_layout.setContentsMargins(0, 0, 0, 0)
                buttons_layout.setSpacing(8)

                btn_restore = QPushButton("🔄 Restore")
                btn_restore.setFixedHeight(35)
                btn_restore.setStyleSheet(f"""
                    QPushButton {{
                        background-color: {ACCENT_COLOR};
                        color: white; border: none; border-radius: 6px;
                        padding: 0 15px; font-size: 12px; font-weight: bold;
                    }}
                    QPushButton:hover {{ background-color: #0070e6; }}
                """)
                btn_restore.clicked.connect(lambda: self.restore_file_action(file_entry.get("id")))

                btn_delete = QPushButton("🗑️ Delete Forever")
                btn_delete.setFixedHeight(35)
                btn_delete.setStyleSheet(f"""
                    QPushButton {{
                        background-color: rgba(217, 48, 37, 0.1);
                        color: {ERROR_COLOR}; border: 1px solid {ERROR_COLOR};
                        border-radius: 6px; padding: 0 15px; font-size: 12px;
                    }}
                    QPushButton:hover {{ background-color: rgba(217, 48, 37, 0.2); }}
                """)
                btn_delete.clicked.connect(lambda: self.delete_permanently_action(file_entry.get("id"), filename))

                buttons_layout.addWidget(btn_restore)
                buttons_layout.addWidget(btn_delete)
                buttons_layout.addStretch()

                # Add all rows to card
                layout.addWidget(info_row)
                layout.addWidget(details_label)
                layout.addWidget(buttons_row)

                return card

            @Slot()
            def restore_file_action(self, file_id):
                """Restore file from archive back to vault"""
                try:
                    archive_manager = ArchiveManager(self.manager.usb_root, self.manager.key)

                    # Restore file
                    file_data, error = archive_manager.restore_file(file_id)

                    if error:
                        print(f"[Archive] Restore failed: {error}")
                        return

                    # Add file back to vault
                    vault_path = os.path.join(self.manager.usb_root, ".dll", "vault.enc")

                    # Load current vault
                    current_vault = self.manager.vault_manager.decrypt_vault(
                        self.manager.usb_root,
                        self.manager.key
                    )

                    # Add restored file
                    current_vault["files"][file_data["path"]] = list(file_data["content"])

                    # Re-encrypt vault
                    self.manager.vault_manager.encrypt_vault(
                        self.manager.usb_root,
                        self.manager.key,
                        current_vault
                    )

                    # Log event
                    filename = os.path.basename(file_data["path"])
                    append_log(self.manager.usb_root, self.manager.key, f"File Restored: {filename}")

                    print(f"[Archive] File restored: {filename}")

                    # Reload archive display
                    self.load_archived_files()

                except Exception as e:
                    print(f"[Archive] Restore error: {e}")
                    import traceback
                    traceback.print_exc()

            @Slot()
            def delete_permanently_action(self, file_id, filename):
                """Permanently delete file from archive"""
                # Confirmation dialog
                reply = QMessageBox.question(
                    self,
                    "Delete Forever",
                    f"Are you sure you want to permanently delete '{filename}'?\n\n"
                    "This action cannot be undone!",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No
                )

                if reply == QMessageBox.Yes:
                    try:
                        archive_manager = ArchiveManager(self.manager.usb_root, self.manager.key)
                        success = archive_manager.delete_permanently(file_id)

                        if success:
                            # Log event
                            append_log(self.manager.usb_root, self.manager.key, f"File Permanently Deleted: {filename}")
                            print(f"[Archive] Permanently deleted: {filename}")

                            # Reload archive display
                            self.load_archived_files()
                        else:
                            print(f"[Archive] Failed to delete: {filename}")

                    except Exception as e:
                        print(f"[Archive] Delete error: {e}")

            def open_vault_folder(self):
                """Open the vault folder in file explorer."""
                if os.path.exists(self.temp_path):
                    if sys.platform == 'win32':
                        subprocess.Popen(f'explorer "{os.path.realpath(self.temp_path)}"')
                    elif sys.platform == 'darwin':
                        subprocess.Popen(['open', self.temp_path])
                    else:
                        subprocess.Popen(['xdg-open', self.temp_path])

            # ==================== SIGNAL HANDLERS ====================

            @Slot(str)
            def on_status_update(self, text):
                """Handle status updates."""
                self.detecting_status.setText(text)

            @Slot(str)
            def on_usb_detected(self, usb_path):
                """USB detected - go to PIN entry"""
                self.usb_root = usb_path
                self.stacked_widget.setCurrentIndex(1)  # Go to PIN entry screen
                self.pin_input.setFocus()

            @Slot()
            def on_pin_verified(self):
                """PIN verified - go to main menu"""
                self.vault_key = self.manager.key
                self.pin_status.setText("✅ PIN Verified!")
                QTimer.singleShot(500, lambda: self.stacked_widget.setCurrentIndex(2))  # Go to main menu

            @Slot()
            def on_pin_incorrect(self):
                """Handle incorrect PIN feedback."""
                self.update_shake_keyframes()
                self.shake_animation.start()

                self.pin_status.setText("❌ Incorrect PIN\nTry again")
                self.pin_status.setStyleSheet(f"color: {ERROR_COLOR}; background: transparent;")
                self.pin_input.setEnabled(True)
                self.pin_input.clear()
                self.pin_input.setFocus()

            @Slot(str)
            def on_vault_mounted(self, temp_path):
                """Vault mounted - go to vault open screen"""
                self.temp_path = temp_path
                self.stacked_widget.setCurrentIndex(3)  # Go to vault open screen

            @Slot()
            def on_vault_locked(self):
                """Vault locked - back to main menu"""
                self.stacked_widget.setCurrentIndex(2)  # Back to main menu

            @Slot(list)
            def display_logs(self, logs):
                """Display logs in text area"""
                if not logs:
                    self.log_display.setText("No logs found.")
                    return

                log_text = "===== VAULT ACCESS LOGS (Newest First) =====\n\n"

                for entry in logs:
                    log_text += f"Time: {entry.get('timestamp', 'Unknown')}\n"
                    log_text += f"Event: {entry.get('event', 'Unknown')}\n"
                    log_text += f"PC: {entry.get('pc_name', 'Unknown')}\n"
                    log_text += f"User: {entry.get('username', 'Unknown')}\n"
                    log_text += f"MAC: {entry.get('mac', 'Unknown')}\n"
                    log_text += f"OS: {entry.get('os_name', 'Unknown')} {entry.get('os_version', '')}\n"
                    log_text += f"CPU: {entry.get('cpu', 'Unknown')}\n"
                    log_text += f"RAM: {entry.get('ram_gb', 'Unknown')} GB\n"
                    log_text += "-" * 60 + "\n\n"

                self.log_display.setText(log_text)

            @Slot(str)
            def on_logs_error(self, error):
                """Handle log loading errors"""
                self.log_display.setText(f"Error loading logs:\n{error}")

            # ==================== WINDOW MANAGEMENT ====================

            def mousePressEvent(self, event):
                """Handle mouse press for window dragging."""
                if event.button() == Qt.LeftButton:
                    if self.childAt(event.position().toPoint()) is None:
                        self.drag_pos = event.globalPosition().toPoint()

            def mouseMoveEvent(self, event):
                """Handle mouse move for window dragging."""
                if self.drag_pos:
                    self.move(self.pos() + event.globalPosition().toPoint() - self.drag_pos)
                    self.drag_pos = event.globalPosition().toPoint()

            def mouseReleaseEvent(self, event):
                """Handle mouse release."""
                self.drag_pos = None

            def paintEvent(self, event):
                """Draw glass morphism background."""
                painter = QPainter(self)
                painter.setRenderHint(QPainter.Antialiasing)
                painter.setBrush(GLASS_COLOR)
                painter.setPen(Qt.NoPen)
                painter.drawRoundedRect(self.rect(), 25, 25)

                border_color = QColor(255, 255, 255, 120)
                painter.setPen(border_color)
                painter.setBrush(Qt.NoBrush)
                painter.drawRoundedRect(self.rect().adjusted(0, 0, -1, -1), 25, 25)

            def closeEvent(self, event):
                """Clean up on window close."""
                self.manager.stop()
                self.thread.quit()
                self.thread.wait()
                super().closeEvent(event)

        def main():
            """Main entry point for the application."""
            app = QApplication(sys.argv)
            window = GlassWindow()
            window.show()
            sys.exit(app.exec())

        # ==================== CRITICAL GUARD ====================
        if __name__ == "__main__":
            multiprocessing.freeze_support()
            main()

        # Get system info for notification
        try:
            pc_name = socket.gethostname()
        except:
            pc_name = "Unknown"

        try:
            username = gp.getuser()
        except:
            username = "Unknown"

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Format message
        notification_text = f"""
🔐 *USB Vault Alert*

{message}

📅 Time: {timestamp}
💻 PC: {pc_name}
👤 User: {username}
"""

        # Send to Telegram
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        data = {
            "chat_id": chat_id,
            "text": notification_text,
            "parse_mode": "Markdown"
        }

        response = requests.post(url, data=data, timeout=5)

        if response.status_code == 200:
            print(f"[Telegram] ✅ Notification sent: {message}")
        else:
            print(f"[Telegram] ❌ Failed to send: {response.text}")

    except Exception as e:
        print(f"[Telegram] Error: {e}")
        # Don't fail vault operations if notification fails


# ==================== EMBEDDED: log_manager.py (FIXED VERSION) ====================
def append_log(usb_path, key, event):
    """Log manager functionality - embedded in exe - FIXED VERSION"""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from datetime import datetime
        import secrets
        import socket
        import uuid
        import platform
        import getpass as gp

        # Try to import psutil, but don't fail if not available
        try:
            import psutil
            has_psutil = True
        except ImportError:
            has_psutil = False
            print("[Warning] psutil not installed - RAM info will show as Unknown")

        # ✅ FIXED: Use correct path
        log_file = os.path.join(usb_path, ".dll", "logs.enc")

        # ✅ FIXED: Get system info with better error handling
        def get_cpu_model():
            try:
                if platform.system().lower() == "windows":
                    output = subprocess.check_output(
                        "wmic cpu get Name",
                        shell=True,
                        stderr=subprocess.DEVNULL,
                        timeout=5
                    ).decode(errors="ignore").strip().split("\n")
                    if len(output) > 1 and output[1].strip():
                        return output[1].strip()
            except Exception as e:
                print(f"[CPU Detection] Windows method failed: {e}")

            try:
                if os.path.exists("/proc/cpuinfo"):
                    with open("/proc/cpuinfo", "r") as f:
                        for line in f:
                            if "model name" in line:
                                return line.split(":", 1)[1].strip()
            except Exception as e:
                print(f"[CPU Detection] Linux method failed: {e}")

            try:
                proc = platform.processor()
                if proc:
                    return proc
            except Exception as e:
                print(f"[CPU Detection] Platform method failed: {e}")

            return "Unknown"

        def get_system_info():
            info = {}

            # PC Name
            try:
                info["pc_name"] = socket.gethostname()
            except Exception as e:
                print(f"[System Info] Hostname failed: {e}")
                info["pc_name"] = "Unknown"

            # Username
            try:
                info["username"] = gp.getuser()
            except Exception as e:
                print(f"[System Info] Username failed: {e}")
                info["username"] = "Unknown"

            # MAC Address
            try:
                mac = uuid.getnode()
                info["mac"] = ":".join(f"{(mac >> ele) & 0xff:02x}" for ele in range(40, -1, -8))
            except Exception as e:
                print(f"[System Info] MAC failed: {e}")
                info["mac"] = "Unknown"

            # OS Name
            try:
                info["os_name"] = platform.system()
            except Exception as e:
                print(f"[System Info] OS name failed: {e}")
                info["os_name"] = "Unknown"

            # OS Version
            try:
                info["os_version"] = platform.release()
            except Exception as e:
                print(f"[System Info] OS version failed: {e}")
                info["os_version"] = "Unknown"

            # CPU
            try:
                info["cpu"] = get_cpu_model()
            except Exception as e:
                print(f"[System Info] CPU failed: {e}")
                info["cpu"] = "Unknown"

            # RAM
            try:
                if has_psutil:
                    ram = round(psutil.virtual_memory().total / (1024 ** 3), 2)
                    info["ram_gb"] = ram
                else:
                    info["ram_gb"] = "Unknown"
            except Exception as e:
                print(f"[System Info] RAM failed: {e}")
                info["ram_gb"] = "Unknown"

            return info

        # Load existing logs
        logs = []
        if os.path.exists(log_file):
            try:
                with open(log_file, "rb") as f:
                    encrypted_logs = f.read()
                if len(encrypted_logs) > 12:
                    nonce = encrypted_logs[:12]
                    ciphertext = encrypted_logs[12:]
                    aesgcm = AESGCM(key)
                    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
                    logs = json.loads(plaintext.decode())
            except Exception as e:
                print(f"[Log Loading] Failed to load existing logs: {e}")
                logs = []

        # Create proper log entry with full system info
        try:
            info = get_system_info()
            logs.append({
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "event": event,
                "pc_name": info.get("pc_name", "Unknown"),
                "username": info.get("username", "Unknown"),
                "mac": info.get("mac", "Unknown"),
                "os_name": info.get("os_name", "Unknown"),
                "os_version": info.get("os_version", "Unknown"),
                "cpu": info.get("cpu", "Unknown"),
                "ram_gb": info.get("ram_gb", "Unknown")
            })
        except Exception as e:
            print(f"[Log Entry Creation] Failed: {e}")
            # Fallback: create minimal log entry
            logs.append({
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "event": event,
                "pc_name": "Unknown",
                "username": "Unknown",
                "mac": "Unknown",
                "os_name": "Unknown",
                "os_version": "Unknown",
                "cpu": "Unknown",
                "ram_gb": "Unknown"
            })

        # Encrypt and save
        try:
            nonce = secrets.token_bytes(12)
            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(nonce, json.dumps(logs).encode(), None)

            with open(log_file, "wb") as f:
                f.write(nonce + ciphertext)

            print(f"[Log] Successfully logged: {event}")

        except Exception as e:
            print(f"[Log Saving] Failed to save log: {e}")
            import traceback
            traceback.print_exc()

    except Exception as e:
        print(f"[Log Manager Error]: {e}")
        import traceback
        traceback.print_exc()


# ==================== TOTP HELPER FUNCTIONS ====================
def load_totp_secret(usb_path, key):
    """Load and decrypt TOTP secret"""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        totp_file = os.path.join(usb_path, ".dll", "totp.enc")

        if not os.path.exists(totp_file):
            return None

        with open(totp_file, "rb") as f:
            data = f.read()

        if len(data) < 12:
            return None

        nonce = data[:12]
        ciphertext = data[12:]

        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode()

    except Exception as e:
        print(f"Error loading TOTP: {e}")
        return None


def verify_totp(secret, otp):
    """Verify TOTP code"""
    try:
        import pyotp
        totp = pyotp.TOTP(secret)
        return totp.verify(otp, valid_window=1)  # Allow 30s window
    except:
        return False


def update_pin_in_meta(usb_path, old_key, new_pin):
    """Update PIN in metadata file and re-encrypt everything"""
    try:
        import secrets
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        meta_path = os.path.join(usb_path, ".dll", "meta.key")

        # Load old metadata
        with open(meta_path, "rb") as f:
            content = f.read()

        salt = content[:16]  # Keep same salt

        # Derive new key from new PIN
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=200000
        )
        new_key = kdf.derive(new_pin.encode())

        # Generate new nonce
        new_nonce = secrets.token_bytes(12)

        # Re-encrypt vault with new key
        vault_path = os.path.join(usb_path, ".dll", "vault.enc")
        with open(vault_path, "rb") as f:
            old_vault_data = f.read()

        # Decrypt with old key
        old_meta_nonce = content[16:28]
        aesgcm_old = AESGCM(old_key)
        vault_plaintext = aesgcm_old.decrypt(old_meta_nonce, old_vault_data, None)

        # Re-encrypt with new key
        aesgcm_new = AESGCM(new_key)
        new_vault_ciphertext = aesgcm_new.encrypt(new_nonce, vault_plaintext, None)

        # Write new vault
        with open(vault_path, "wb") as f:
            f.write(new_vault_ciphertext)

        # Write new metadata
        new_meta = salt + new_nonce + bytes([len(new_pin)]) + new_pin.encode()
        with open(meta_path, "wb") as f:
            f.write(new_meta)

        # Re-encrypt TOTP secret with new key
        totp_secret = load_totp_secret(usb_path, old_key)
        if totp_secret:
            totp_nonce = secrets.token_bytes(12)
            totp_ciphertext = aesgcm_new.encrypt(totp_nonce, totp_secret.encode(), None)
            totp_path = os.path.join(usb_path, ".dll", "totp.enc")
            with open(totp_path, "wb") as f:
                f.write(totp_nonce + totp_ciphertext)

        return True

    except Exception as e:
        print(f"Error updating PIN: {e}")
        import traceback
        traceback.print_exc()
        return False


# ==================== EMBEDDED: launcher.py functionality ====================
class VaultManager:
    """All launcher.py functionality embedded here"""

    USB_ROOT = None
    VAULT_DIR_NAME = ".dll"
    META_FILE = "meta.key"
    VAULT_FILE = "vault.enc"
    TEMP_VAULT = r"C:\USBVaultTemp"

    @staticmethod
    def detect_usb():
        """Detect USB drive with vault"""
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            check_path = f"{letter}:\\{VaultManager.VAULT_DIR_NAME}\\{VaultManager.META_FILE}"
            if os.path.exists(check_path):
                return letter + ":"
        return None

    @staticmethod
    def load_meta(usb_path):
        """Load metadata from vault"""
        path = os.path.join(usb_path, VaultManager.VAULT_DIR_NAME, VaultManager.META_FILE)
        with open(path, "rb") as f:
            content = f.read()

        salt = content[:16]
        nonce = content[16:28]
        pin_len = content[28]
        pin = content[29:29 + pin_len].decode()

        return salt, nonce, pin

    @staticmethod
    def derive_key(pin, salt):
        """Derive encryption key from PIN"""
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=200000
        )
        return kdf.derive(pin.encode())

    @staticmethod
    def decrypt_vault(usb_path, key):
        """Decrypt vault"""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        vault_path = os.path.join(usb_path, VaultManager.VAULT_DIR_NAME, VaultManager.VAULT_FILE)
        meta_path = os.path.join(usb_path, VaultManager.VAULT_DIR_NAME, VaultManager.META_FILE)

        with open(vault_path, "rb") as f:
            ct = f.read()
        with open(meta_path, "rb") as f:
            meta = f.read()

        nonce = meta[16:28]

        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ct, None)
        return json.loads(plaintext.decode())

    @staticmethod
    def encrypt_vault(usb_path, key, data):
        """Re-encrypt vault"""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import secrets

        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)

        ct = aesgcm.encrypt(nonce, json.dumps(data).encode(), None)

        vault_path = os.path.join(usb_path, VaultManager.VAULT_DIR_NAME, VaultManager.VAULT_FILE)
        meta_path = os.path.join(usb_path, VaultManager.VAULT_DIR_NAME, VaultManager.META_FILE)

        with open(vault_path, "wb") as f:
            f.write(ct)

        # Keep same salt + PIN, replace nonce
        with open(meta_path, "rb") as f:
            content = f.read()

        salt = content[:16]
        pin_len = content[28]
        pin = content[29:29 + pin_len]

        new_meta = salt + nonce + bytes([pin_len]) + pin

        with open(meta_path, "wb") as f:
            f.write(new_meta)


# ==================== LOG VIEWER FUNCTIONALITY ====================
class LogViewerManager(QObject):
    """Handles log loading and decryption"""
    logs_loaded = Signal(list)
    error_occurred = Signal(str)

    def __init__(self, usb_path, key):
        super().__init__()
        self.usb_path = usb_path
        self.key = key

    def load_logs(self):
        """Load and decrypt logs"""
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            log_file = os.path.join(self.usb_path, ".dll", "logs.enc")

            if not os.path.exists(log_file):
                self.logs_loaded.emit([])
                return

            with open(log_file, "rb") as f:
                data = f.read()

            if len(data) < 12:
                self.logs_loaded.emit([])
                return

            nonce = data[:12]
            ciphertext = data[12:]

            aesgcm = AESGCM(self.key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            logs = json.loads(plaintext.decode())

            # Reverse for newest first
            self.logs_loaded.emit(list(reversed(logs)))

        except Exception as e:
            self.error_occurred.emit(f"Failed to load logs: {str(e)}")


# ==================== ARCHIVE MANAGER ====================
class ArchiveManager:
    """Manages archived (deleted) files with 30-day retention"""

    ARCHIVE_FILE = "archive.enc"
    RETENTION_DAYS = 30

    def __init__(self, usb_path, key):
        self.usb_path = usb_path
        self.key = key
        self.archive_path = os.path.join(usb_path, ".dll", self.ARCHIVE_FILE)

    def load_archive(self):
        """Load and decrypt archive"""
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            if not os.path.exists(self.archive_path):
                return {"archived_files": []}

            with open(self.archive_path, "rb") as f:
                data = f.read()

            if len(data) < 12:
                return {"archived_files": []}

            nonce = data[:12]
            ciphertext = data[12:]

            aesgcm = AESGCM(self.key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return json.loads(plaintext.decode())

        except Exception as e:
            print(f"[Archive] Error loading archive: {e}")
            return {"archived_files": []}

    def save_archive(self, archive_data):
        """Encrypt and save archive"""
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            import secrets

            nonce = secrets.token_bytes(12)
            aesgcm = AESGCM(self.key)
            ciphertext = aesgcm.encrypt(nonce, json.dumps(archive_data).encode(), None)

            with open(self.archive_path, "wb") as f:
                f.write(nonce + ciphertext)

            return True
        except Exception as e:
            print(f"[Archive] Error saving archive: {e}")
            return False

    def archive_file(self, filename, original_path, content):
        """Archive a deleted file"""
        try:
            from datetime import datetime
            import uuid

            archive_data = self.load_archive()

            # Calculate file size
            file_size = len(content)
            if file_size < 1024:
                size_readable = f"{file_size} B"
            elif file_size < 1024 * 1024:
                size_readable = f"{file_size / 1024:.1f} KB"
            else:
                size_readable = f"{file_size / (1024 * 1024):.1f} MB"

            # Create archive entry
            now = datetime.now()
            entry = {
                "id": str(uuid.uuid4()),
                "filename": filename,
                "original_path": original_path,
                "deleted_date": now.strftime("%Y-%m-%d"),
                "deleted_time": now.strftime("%H:%M:%S"),
                "deleted_timestamp": now.timestamp(),
                "file_size_bytes": file_size,
                "file_size_readable": size_readable,
                "content": list(content)
            }

            archive_data["archived_files"].append(entry)
            return self.save_archive(archive_data)

        except Exception as e:
            print(f"[Archive] Error archiving file: {e}")
            return False

    def cleanup_old_files(self):
        """Delete files older than 30 days"""
        try:
            from datetime import datetime, timedelta

            archive_data = self.load_archive()
            cutoff_timestamp = (datetime.now() - timedelta(days=self.RETENTION_DAYS)).timestamp()

            original_count = len(archive_data["archived_files"])

            # Filter out old files
            archive_data["archived_files"] = [
                f for f in archive_data["archived_files"]
                if f.get("deleted_timestamp", 0) > cutoff_timestamp
            ]

            deleted_count = original_count - len(archive_data["archived_files"])

            if deleted_count > 0:
                self.save_archive(archive_data)
                print(f"[Archive] Auto-deleted {deleted_count} files older than {self.RETENTION_DAYS} days")
                return deleted_count

            return 0

        except Exception as e:
            print(f"[Archive] Error cleaning up old files: {e}")
            return 0

    def get_files_grouped_by_month(self):
        """Get archived files grouped by month/year"""
        try:
            from datetime import datetime
            from collections import defaultdict

            archive_data = self.load_archive()
            grouped = defaultdict(list)

            for file_entry in archive_data["archived_files"]:
                try:
                    date_str = file_entry.get("deleted_date", "")
                    date_obj = datetime.strptime(date_str, "%Y-%m-%d")
                    month_key = date_obj.strftime("%B %Y")  # e.g., "November 2025"

                    # Calculate days remaining
                    deleted_timestamp = file_entry.get("deleted_timestamp", 0)
                    now_timestamp = datetime.now().timestamp()
                    days_old = int((now_timestamp - deleted_timestamp) / 86400)
                    days_remaining = self.RETENTION_DAYS - days_old

                    file_entry["days_remaining"] = max(0, days_remaining)
                    grouped[month_key].append(file_entry)
                except:
                    continue

            # Sort months (newest first)
            sorted_groups = []
            for month_key in sorted(grouped.keys(), reverse=True,
                                    key=lambda x: datetime.strptime(x, "%B %Y")):
                sorted_groups.append({
                    "month": month_key,
                    "files": sorted(grouped[month_key],
                                    key=lambda x: x.get("deleted_timestamp", 0),
                                    reverse=True)
                })

            return sorted_groups

        except Exception as e:
            print(f"[Archive] Error grouping files: {e}")
            return []

    def restore_file(self, file_id):
        """Restore file from archive back to vault"""
        try:
            archive_data = self.load_archive()

            # Find file by ID
            file_to_restore = None
            for i, f in enumerate(archive_data["archived_files"]):
                if f.get("id") == file_id:
                    file_to_restore = archive_data["archived_files"].pop(i)
                    break

            if not file_to_restore:
                return None, "File not found in archive"

            # Save updated archive
            self.save_archive(archive_data)

            # Return file data for adding back to vault
            return {
                "path": file_to_restore.get("original_path"),
                "content": bytes(file_to_restore.get("content", []))
            }, None

        except Exception as e:
            print(f"[Archive] Error restoring file: {e}")
            return None, str(e)

    def delete_permanently(self, file_id):
        """Permanently delete file from archive"""
        try:
            archive_data = self.load_archive()

            # Remove file by ID
            original_count = len(archive_data["archived_files"])
            archive_data["archived_files"] = [
                f for f in archive_data["archived_files"]
                if f.get("id") != file_id
            ]

            if len(archive_data["archived_files"]) < original_count:
                self.save_archive(archive_data)
                return True

            return False

        except Exception as e:
            print(f"[Archive] Error deleting file: {e}")
            return False

    def get_statistics(self):
        """Get archive statistics"""
        try:
            archive_data = self.load_archive()
            files = archive_data["archived_files"]

            if not files:
                return {
                    "total_files": 0,
                    "total_size_bytes": 0,
                    "total_size_readable": "0 B"
                }

            total_size = sum(f.get("file_size_bytes", 0) for f in files)

            if total_size < 1024:
                size_readable = f"{total_size} B"
            elif total_size < 1024 * 1024:
                size_readable = f"{total_size / 1024:.1f} KB"
            else:
                size_readable = f"{total_size / (1024 * 1024):.1f} MB"

            return {
                "total_files": len(files),
                "total_size_bytes": total_size,
                "total_size_readable": size_readable
            }

        except Exception as e:
            print(f"[Archive] Error getting statistics: {e}")
            return {"total_files": 0, "total_size_bytes": 0, "total_size_readable": "0 B"}


# ==================== 🎨 Premium Palette ====================
GLASS_COLOR = QColor(255, 255, 255, 180)
ACCENT_COLOR = "#007AFF"
TEXT_COLOR = "#222222"
ERROR_COLOR = "#D93025"
SUCCESS_COLOR = "#4CAF50"
WARNING_COLOR = "#FF9800"

CLOSE_BTN_BG = "rgba(255, 255, 255, 40)"
CLOSE_BTN_HOVER = "rgba(255, 255, 255, 80)"
CLOSE_BTN_PRESSED = "rgba(255, 0, 0, 60)"


# ==================== WORKER THREAD (Vault Process Manager) ====================
class VaultProcessManager(QObject):
    status_updated = Signal(str)
    usb_detected = Signal(str)
    pin_verified = Signal()
    pin_incorrect = Signal()
    vault_mounted = Signal(str)
    vault_locked = Signal()

    def __init__(self):
        super().__init__()
        self.vault_manager = VaultManager()
        self.usb_root = None
        self.key = None
        self.user_pin = None
        self.vault_data = None

    def run(self):
        """Start the vault detection process."""
        try:
            print("Detecting secure USB...")
            self.status_updated.emit("Detecting secure USB...")

            # Detect USB
            self.usb_root = self.vault_manager.detect_usb()
            if self.usb_root is None:
                self.status_updated.emit("❌ Secure USB not detected. Please insert USB drive.")
                print("❌ Secure USB not detected.")
                return

            print(f"✔ USB found at {self.usb_root}")
            self.status_updated.emit(f"✔ USB found at {self.usb_root}")

            # 📱 Send notification - USB plugged in
            send_telegram_notification("⚠️ Someone plugged in the USB vault!")

            self.usb_detected.emit(self.usb_root)

        except Exception as e:
            error_msg = f"Error: {str(e)}"
            self.status_updated.emit(error_msg)
            print(f"[Error in VaultProcessManager]: {e}")
            import traceback
            traceback.print_exc()

    def verify_pin(self, user_pin):
        """Verify PIN"""
        try:
            # Load metadata
            salt, nonce, correct_pin = self.vault_manager.load_meta(self.usb_root)

            if user_pin != correct_pin:
                self.status_updated.emit("Incorrect PIN")
                self.pin_incorrect.emit()
                print("❌ Incorrect PIN.")

                # 📱 Send notification - Wrong PIN
                send_telegram_notification(
                    "❌ *ALERT: Wrong PIN entered!*\nSomeone tried to access the vault with incorrect PIN.")

                return

            print("✔ PIN verified")
            self.status_updated.emit("✔ PIN verified")

            # Derive key and store
            self.key = self.vault_manager.derive_key(user_pin, salt)
            self.user_pin = user_pin

            # 📱 Send notification - Correct PIN
            send_telegram_notification("✅ *Vault Accessed Successfully*\nCorrect PIN was entered.")

            self.pin_verified.emit()

        except Exception as e:
            error_msg = f"Error: {str(e)}"
            self.status_updated.emit(error_msg)
            print(f"[Error verifying PIN]: {e}")
            import traceback
            traceback.print_exc()

    def mount_vault(self):
        """Mount and decrypt vault with auto-cleanup"""
        try:
            if not self.usb_root or not self.key:
                self.status_updated.emit("Error: Not authenticated")
                return

            print("Mounting vault...")
            self.status_updated.emit("Mounting vault...")

            # Auto-cleanup old archived files (30+ days)
            try:
                archive_manager = ArchiveManager(self.usb_root, self.key)
                deleted_count = archive_manager.cleanup_old_files()
                if deleted_count > 0:
                    append_log(self.usb_root, self.key, f"Auto-deleted {deleted_count} archived files (30+ days old)")
            except Exception as e:
                print(f"[Archive] Cleanup failed: {e}")

            # Create temp folder
            if os.path.exists(self.vault_manager.TEMP_VAULT):
                shutil.rmtree(self.vault_manager.TEMP_VAULT)
            os.makedirs(self.vault_manager.TEMP_VAULT, exist_ok=True)

            # Decrypt vault
            self.vault_data = self.vault_manager.decrypt_vault(self.usb_root, self.key)
            print("✔ Vault decrypted")
            self.status_updated.emit("✔ Vault decrypted")

            # Log the event
            append_log(self.usb_root, self.key, "Vault Opened")

            # 📱 Send notification - Vault opened
            send_telegram_notification("🔓 *Vault Opened*\nFiles are now accessible.")

            # Extract decrypted files to TEMP
            for name, content in self.vault_data["files"].items():
                file_path = os.path.join(self.vault_manager.TEMP_VAULT, name)
                os.makedirs(os.path.dirname(file_path), exist_ok=True)

                with open(file_path, "wb") as f:
                    f.write(bytes(content))

            print(f"Vault opened at: {self.vault_manager.TEMP_VAULT}")
            self.vault_mounted.emit(self.vault_manager.TEMP_VAULT)

        except Exception as e:
            error_msg = f"Error: {str(e)}"
            self.status_updated.emit(error_msg)
            print(f"[Error mounting vault]: {e}")
            import traceback
            traceback.print_exc()

    def lock_vault(self):
        """Re-encrypt and lock the vault with archive support"""
        try:
            if not self.usb_root or not self.key:
                self.status_updated.emit("Error: Vault not unlocked")
                return

            print("Rebuilding vault...")
            self.status_updated.emit("Rebuilding vault...")

            # Get old vault data (what was there before)
            old_vault_data = self.vault_data if self.vault_data else {"files": {}}

            # Rebuild vault from temp files (current state)
            new_data = {"files": {}}

            for root, dirs, files in os.walk(self.vault_manager.TEMP_VAULT):
                for file in files:
                    p = os.path.join(root, file)
                    rel_path = os.path.relpath(p, self.vault_manager.TEMP_VAULT)

                    with open(p, "rb") as f:
                        new_data["files"][rel_path] = list(f.read())

            # Detect deleted files (existed before but not now)
            deleted_files = []
            for old_path in old_vault_data.get("files", {}).keys():
                if old_path not in new_data["files"]:
                    deleted_files.append(old_path)

            # Archive deleted files
            if deleted_files:
                print(f"[Archive] Detected {len(deleted_files)} deleted file(s)")
                archive_manager = ArchiveManager(self.usb_root, self.key)

                for file_path in deleted_files:
                    try:
                        filename = os.path.basename(file_path)
                        content = bytes(old_vault_data["files"][file_path])

                        success = archive_manager.archive_file(filename, file_path, content)
                        if success:
                            print(f"[Archive] Archived: {filename}")
                            append_log(self.usb_root, self.key, f"File Archived: {filename}")
                    except Exception as e:
                        print(f"[Archive] Failed to archive {file_path}: {e}")

            # Re-encrypt vault
            self.vault_manager.encrypt_vault(self.usb_root, self.key, new_data)
            print("✔ Vault re-encrypted")
            self.status_updated.emit("✔ Vault re-encrypted")

            # Clean up temp folder
            shutil.rmtree(self.vault_manager.TEMP_VAULT)
            print("✔ Temp folder removed")

            # Log the event
            append_log(self.usb_root, self.key, "Vault Closed")

            # 📱 Send notification - Vault closed
            send_telegram_notification("🔒 *Vault Locked*\nVault has been secured.")

            self.vault_locked.emit()

        except Exception as e:
            error_msg = f"Error: {str(e)}"
            self.status_updated.emit(error_msg)
            print(f"[Error locking vault]: {e}")
            import traceback
            traceback.print_exc()

    def stop(self):
        """Clean up resources."""
        try:
            if os.path.exists(self.vault_manager.TEMP_VAULT):
                shutil.rmtree(self.vault_manager.TEMP_VAULT)
        except Exception as e:
            print(f"Error cleaning up: {e}")


# ==================== MAIN GUI APPLICATION ====================
class GlassWindow(QWidget):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("USB Vault")
        self.resize(600, 520)
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)

        self.drag_pos = None
        self.temp_path = ""
        self.usb_root = None
        self.vault_key = None

        # Screen state tracking
        self.current_screen = "DETECTING"

        # Create widgets and animations
        self.create_widgets()
        self.create_animations()
        self.add_close_button()

        # Setup backend thread
        self.setup_backend_thread()

    def create_widgets(self):
        """Create all GUI widgets with multi-screen support."""
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(40, 50, 40, 50)
        self.main_layout.setSpacing(5)

        # Stacked widget for multiple screens
        self.stacked_widget = QStackedWidget(self)
        self.stacked_widget.setStyleSheet("background: transparent;")

        # Create screens
        self.screen_detecting = self.create_detecting_screen()
        self.screen_pin_entry = self.create_pin_entry_screen()
        self.screen_main_menu = self.create_main_menu_screen()
        self.screen_vault_open = self.create_vault_open_screen()
        self.screen_log_viewer = self.create_log_viewer_screen()
        self.screen_pin_reset = self.create_pin_reset_screen()
        self.screen_archive = self.create_archive_screen()

        # Add screens to stack
        self.stacked_widget.addWidget(self.screen_detecting)  # Index 0
        self.stacked_widget.addWidget(self.screen_pin_entry)  # Index 1
        self.stacked_widget.addWidget(self.screen_main_menu)  # Index 2
        self.stacked_widget.addWidget(self.screen_vault_open)  # Index 3
        self.stacked_widget.addWidget(self.screen_log_viewer)  # Index 4
        self.stacked_widget.addWidget(self.screen_pin_reset)  # Index 5
        self.stacked_widget.addWidget(self.screen_archive)  # Index 6

        self.main_layout.addWidget(self.stacked_widget)

        # Start on detecting screen
        self.stacked_widget.setCurrentIndex(0)

    def create_detecting_screen(self):
        """Screen 0: USB Detection"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setAlignment(Qt.AlignCenter)
        layout.setSpacing(20)

        title = QLabel("🔍 Detecting USB Vault")
        title.setFont(QFont("Arial", 24, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {TEXT_COLOR}; background: transparent;")
        title.setAlignment(Qt.AlignCenter)

        status = QLabel("Please insert your USB vault...")
        status.setFont(QFont("Arial", 12))
        status.setStyleSheet(f"color: {TEXT_COLOR}; background: transparent;")
        status.setAlignment(Qt.AlignCenter)

        layout.addStretch()
        layout.addWidget(title)
        layout.addWidget(status)
        layout.addStretch()

        self.detecting_status = status
        return widget

    def create_pin_entry_screen(self):
        """Screen 1: PIN Entry"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setAlignment(Qt.AlignCenter)
        layout.setSpacing(20)

        title = QLabel("🔐 Enter PIN")
        title.setFont(QFont("Arial", 24, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {TEXT_COLOR}; background: transparent;")
        title.setAlignment(Qt.AlignCenter)

        status = QLabel("Vault detected. Please enter your PIN.")
        status.setFont(QFont("Arial", 12))
        status.setStyleSheet(f"color: {TEXT_COLOR}; background: transparent;")
        status.setWordWrap(True)
        status.setAlignment(Qt.AlignCenter)

        # PIN Input
        pin_input = QLineEdit()
        pin_input.setEchoMode(QLineEdit.Password)
        pin_input.setPlaceholderText("Enter PIN")
        pin_input.setFixedSize(220, 50)
        pin_input.setAlignment(Qt.AlignCenter)
        pin_input.setFont(QFont("Arial", 14))
        pin_input.returnPressed.connect(self.verify_pin)
        pin_input.setStyleSheet(f"""
            QLineEdit {{
                background-color: rgba(0, 0, 0, 0.05);
                border: 2px solid rgba(0, 0, 0, 0.1);
                border-radius: 25px; padding: 0 15px; color: {TEXT_COLOR};
            }}
            QLineEdit:focus {{ border: 2px solid {ACCENT_COLOR}; }}
        """)

        # Unlock Button
        unlock_btn = QPushButton("Unlock")
        unlock_btn.setFixedSize(200, 55)
        unlock_btn.setFont(QFont("Arial", 16, QFont.Weight.DemiBold))
        unlock_btn.clicked.connect(self.verify_pin)
        unlock_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {ACCENT_COLOR};
                color: white; border: none; border-radius: 27px;
            }}
            QPushButton:hover {{ background-color: #0070e6; }}
            QPushButton:pressed {{ background-color: #0062cc; }}
        """)

        layout.addStretch()
        layout.addWidget(title)
        layout.addWidget(status)
        layout.addWidget(pin_input, alignment=Qt.AlignCenter)
        layout.addWidget(unlock_btn, alignment=Qt.AlignCenter)
        layout.addStretch()

        self.pin_input = pin_input
        self.pin_status = status
        return widget

    def create_main_menu_screen(self):
        """Screen 2: Main Menu (after PIN verified)"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setAlignment(Qt.AlignCenter)
        layout.setSpacing(15)

        title = QLabel("✅ Authenticated")
        title.setFont(QFont("Arial", 24, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {TEXT_COLOR}; background: transparent;")
        title.setAlignment(Qt.AlignCenter)

        subtitle = QLabel("Choose an action:")
        subtitle.setFont(QFont("Arial", 13))
        subtitle.setStyleSheet(f"color: {TEXT_COLOR}; background: transparent;")
        subtitle.setAlignment(Qt.AlignCenter)

        # Open Vault Button
        btn_open_vault = QPushButton("🔓 Open Vault")
        btn_open_vault.setFixedSize(280, 55)
        btn_open_vault.setFont(QFont("Arial", 14, QFont.Weight.DemiBold))
        btn_open_vault.clicked.connect(self.open_vault_action)
        btn_open_vault.setStyleSheet(f"""
            QPushButton {{
                background-color: {ACCENT_COLOR};
                color: white; border: none; border-radius: 27px;
            }}
            QPushButton:hover {{ background-color: #0070e6; }}
        """)

        # View Logs Button
        btn_view_logs = QPushButton("📋 View Logs")
        btn_view_logs.setFixedSize(280, 55)
        btn_view_logs.setFont(QFont("Arial", 14, QFont.Weight.DemiBold))
        btn_view_logs.clicked.connect(self.view_logs_action)
        btn_view_logs.setStyleSheet(f"""
            QPushButton {{
                background-color: rgba(0, 122, 255, 0.15);
                color: {ACCENT_COLOR}; border: 2px solid {ACCENT_COLOR};
                border-radius: 27px;
            }}
            QPushButton:hover {{ background-color: rgba(0, 122, 255, 0.25); }}
        """)

        # Archive Button
        btn_archive = QPushButton("📦 Deleted Files")
        btn_archive.setFixedSize(280, 55)
        btn_archive.setFont(QFont("Arial", 14, QFont.Weight.DemiBold))
        btn_archive.clicked.connect(self.view_archive_action)
        btn_archive.setStyleSheet(f"""
            QPushButton {{
                background-color: rgba(156, 39, 176, 0.15);
                color: #9C27B0; border: 2px solid #9C27B0;
                border-radius: 27px;
            }}
            QPushButton:hover {{ background-color: rgba(156, 39, 176, 0.25); }}
        """)

        # PIN Reset Button
        btn_reset_pin = QPushButton("🔑 Reset PIN")
        btn_reset_pin.setFixedSize(280, 55)
        btn_reset_pin.setFont(QFont("Arial", 14, QFont.Weight.DemiBold))
        btn_reset_pin.clicked.connect(self.reset_pin_action)
        btn_reset_pin.setStyleSheet(f"""
            QPushButton {{
                background-color: rgba(255, 152, 0, 0.15);
                color: {WARNING_COLOR}; border: 2px solid {WARNING_COLOR};
                border-radius: 27px;
            }}
            QPushButton:hover {{ background-color: rgba(255, 152, 0, 0.25); }}
        """)

        layout.addStretch()
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addSpacing(15)
        layout.addWidget(btn_open_vault, alignment=Qt.AlignCenter)
        layout.addWidget(btn_view_logs, alignment=Qt.AlignCenter)
        layout.addWidget(btn_archive, alignment=Qt.AlignCenter)
        layout.addWidget(btn_reset_pin, alignment=Qt.AlignCenter)
        layout.addStretch()

        return widget

    def create_vault_open_screen(self):
        """Screen 3: Vault Open"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setAlignment(Qt.AlignCenter)
        layout.setSpacing(20)

        title = QLabel("🔓 Vault Open")
        title.setFont(QFont("Arial", 24, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {TEXT_COLOR}; background: transparent;")
        title.setAlignment(Qt.AlignCenter)

        status = QLabel("Your vault is accessible.\nEdit files, then lock when done.")
        status.setFont(QFont("Arial", 12))
        status.setStyleSheet(f"color: {TEXT_COLOR}; background: transparent;")
        status.setWordWrap(True)
        status.setAlignment(Qt.AlignCenter)

        # Open Folder Button
        btn_open_folder = QPushButton("📁 Open Folder")
        btn_open_folder.setFixedSize(250, 55)
        btn_open_folder.setFont(QFont("Arial", 14, QFont.Weight.DemiBold))
        btn_open_folder.clicked.connect(self.open_vault_folder)
        btn_open_folder.setStyleSheet(f"""
            QPushButton {{
                background-color: rgba(0, 122, 255, 0.1);
                color: {ACCENT_COLOR}; border: 2px solid {ACCENT_COLOR};
                border-radius: 27px;
            }}
            QPushButton:hover {{ background-color: rgba(0, 122, 255, 0.2); }}
        """)

        # Lock Vault Button
        btn_lock_vault = QPushButton("🔒 Lock Vault")
        btn_lock_vault.setFixedSize(250, 55)
        btn_lock_vault.setFont(QFont("Arial", 14, QFont.Weight.DemiBold))
        btn_lock_vault.clicked.connect(self.lock_vault_action)
        btn_lock_vault.setStyleSheet(f"""
            QPushButton {{
                background-color: {ACCENT_COLOR};
                color: white; border: none; border-radius: 27px;
            }}
            QPushButton:hover {{ background-color: #0070e6; }}
        """)

        # Back to Menu Button
        btn_back = QPushButton("← Back to Menu")
        btn_back.setFixedSize(180, 45)
        btn_back.setFont(QFont("Arial", 12))
        btn_back.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(2))
        btn_back.setStyleSheet(f"""
            QPushButton {{
                background-color: transparent;
                color: {TEXT_COLOR}; border: 1px solid rgba(0,0,0,0.2);
                border-radius: 22px;
            }}
            QPushButton:hover {{ background-color: rgba(0,0,0,0.05); }}
        """)

        layout.addStretch()
        layout.addWidget(title)
        layout.addWidget(status)
        layout.addSpacing(15)
        layout.addWidget(btn_open_folder, alignment=Qt.AlignCenter)
        layout.addWidget(btn_lock_vault, alignment=Qt.AlignCenter)
        layout.addSpacing(10)
        layout.addWidget(btn_back, alignment=Qt.AlignCenter)
        layout.addStretch()

        return widget

    def create_log_viewer_screen(self):
        """Screen 4: Log Viewer"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(15)

        # Header
        header = QWidget()
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(0, 0, 0, 0)

        title = QLabel("📋 Forensic Logs")
        title.setFont(QFont("Arial", 20, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {TEXT_COLOR}; background: transparent;")

        btn_back = QPushButton("← Back")
        btn_back.setFixedSize(100, 35)
        btn_back.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(2))
        btn_back.setStyleSheet(f"""
            QPushButton {{
                background-color: rgba(0,0,0,0.05);
                border: 1px solid rgba(0,0,0,0.1);
                border-radius: 17px; color: {TEXT_COLOR};
            }}
            QPushButton:hover {{ background-color: rgba(0,0,0,0.1); }}
        """)

        header_layout.addWidget(title)
        header_layout.addStretch()
        header_layout.addWidget(btn_back)

        # Log display area
        log_display = QTextEdit()
        log_display.setReadOnly(True)
        log_display.setStyleSheet(f"""
            QTextEdit {{
                background-color: rgba(0, 0, 0, 0.03);
                border: 1px solid rgba(0, 0, 0, 0.1);
                border-radius: 12px;
                padding: 15px;
                color: {TEXT_COLOR};
                font-family: 'Courier New', monospace;
                font-size: 11px;
            }}
        """)

        layout.addWidget(header)
        layout.addWidget(log_display)

        self.log_display = log_display
        return widget

    def create_pin_reset_screen(self):
        """Screen 5: PIN Reset with 2FA"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setAlignment(Qt.AlignCenter)
        layout.setSpacing(15)
        layout.setContentsMargins(40, 30, 40, 30)

        title = QLabel("🔑 Reset PIN")
        title.setFont(QFont("Arial", 22, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {TEXT_COLOR}; background: transparent;")
        title.setAlignment(Qt.AlignCenter)

        subtitle = QLabel("Verify your identity with current PIN and 2FA code")
        subtitle.setFont(QFont("Arial", 11))
        subtitle.setStyleSheet(f"color: {TEXT_COLOR}; background: transparent;")
        subtitle.setWordWrap(True)
        subtitle.setAlignment(Qt.AlignCenter)

        # Form container
        form_widget = QWidget()
        form_widget.setMaximumWidth(400)
        form_layout = QFormLayout(form_widget)
        form_layout.setSpacing(12)
        form_layout.setLabelAlignment(Qt.AlignRight)

        input_style = f"""
            QLineEdit {{
                background-color: rgba(0, 0, 0, 0.05);
                border: 2px solid rgba(0, 0, 0, 0.1);
                border-radius: 8px; padding: 0 12px; color: {TEXT_COLOR};
                font-size: 13px;
            }}
            QLineEdit:focus {{ border: 2px solid {ACCENT_COLOR}; }}
        """

        # Current PIN
        current_pin_input = QLineEdit()
        current_pin_input.setEchoMode(QLineEdit.Password)
        current_pin_input.setPlaceholderText("Current PIN")
        current_pin_input.setFixedHeight(45)
        current_pin_input.setStyleSheet(input_style)

        # TOTP Code
        totp_input = QLineEdit()
        totp_input.setPlaceholderText("6-digit code")
        totp_input.setFixedHeight(45)
        totp_input.setMaxLength(6)
        totp_input.setStyleSheet(input_style)

        # Hint label for TOTP
        totp_hint = QLabel("Open Google Authenticator app")
        totp_hint.setFont(QFont("Arial", 9))
        totp_hint.setStyleSheet(f"color: rgba(34, 34, 34, 0.6); background: transparent;")

        # New PIN
        new_pin_input = QLineEdit()
        new_pin_input.setEchoMode(QLineEdit.Password)
        new_pin_input.setPlaceholderText("New PIN")
        new_pin_input.setFixedHeight(45)
        new_pin_input.setStyleSheet(input_style)

        # Confirm New PIN
        confirm_pin_input = QLineEdit()
        confirm_pin_input.setEchoMode(QLineEdit.Password)
        confirm_pin_input.setPlaceholderText("Confirm New PIN")
        confirm_pin_input.setFixedHeight(45)
        confirm_pin_input.setStyleSheet(input_style)

        # Add fields to form
        form_layout.addRow("Current PIN:", current_pin_input)
        form_layout.addRow("2FA Code:", totp_input)
        form_layout.addRow("", totp_hint)
        form_layout.addRow("New PIN:", new_pin_input)
        form_layout.addRow("Confirm:", confirm_pin_input)

        # Status label
        status_label = QLabel("")
        status_label.setFont(QFont("Arial", 11))
        status_label.setStyleSheet(f"color: {TEXT_COLOR}; background: transparent;")
        status_label.setAlignment(Qt.AlignCenter)
        status_label.setWordWrap(True)
        status_label.setMinimumHeight(40)

        # Buttons
        button_container = QWidget()
        button_layout = QHBoxLayout(button_container)
        button_layout.setSpacing(10)

        btn_cancel = QPushButton("Cancel")
        btn_cancel.setFixedSize(120, 45)
        btn_cancel.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(2))
        btn_cancel.setStyleSheet(f"""
            QPushButton {{
                background-color: rgba(0,0,0,0.05);
                border: 1px solid rgba(0,0,0,0.2);
                border-radius: 22px; color: {TEXT_COLOR};
                font-size: 13px;
            }}
            QPushButton:hover {{ background-color: rgba(0,0,0,0.1); }}
        """)

        btn_reset = QPushButton("Reset PIN")
        btn_reset.setFixedSize(140, 45)
        btn_reset.clicked.connect(self.process_pin_reset)
        btn_reset.setStyleSheet(f"""
            QPushButton {{
                background-color: {ACCENT_COLOR};
                color: white; border: none; border-radius: 22px;
                font-size: 13px; font-weight: bold;
            }}
            QPushButton:hover {{ background-color: #0070e6; }}
        """)

        button_layout.addWidget(btn_cancel)
        button_layout.addWidget(btn_reset)

        layout.addStretch()
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addSpacing(10)
        layout.addWidget(form_widget, alignment=Qt.AlignCenter)
        layout.addWidget(status_label)
        layout.addWidget(button_container, alignment=Qt.AlignCenter)
        layout.addStretch()

        # Store references
        self.reset_current_pin = current_pin_input
        self.reset_totp = totp_input
        self.reset_new_pin = new_pin_input
        self.reset_confirm_pin = confirm_pin_input
        self.reset_status = status_label

        return widget

    def create_archive_screen(self):
        """Screen 6: Archive (Deleted Files) Viewer"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(15)

        # Header
        header = QWidget()
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(0, 0, 0, 0)

        title = QLabel("📦 Deleted Files Archive")
        title.setFont(QFont("Arial", 20, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {TEXT_COLOR}; background: transparent;")

        # Stats label
        stats_label = QLabel("Loading...")
        stats_label.setFont(QFont("Arial", 10))
        stats_label.setStyleSheet(f"color: {TEXT_COLOR}; background: transparent;")

        btn_back = QPushButton("← Back")
        btn_back.setFixedSize(100, 35)
        btn_back.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(2))
        btn_back.setStyleSheet(f"""
            QPushButton {{
                background-color: rgba(0,0,0,0.05);
                border: 1px solid rgba(0,0,0,0.1);
                border-radius: 17px; color: {TEXT_COLOR};
            }}
            QPushButton:hover {{ background-color: rgba(0,0,0,0.1); }}
        """)

        header_layout.addWidget(title)
        header_layout.addWidget(stats_label)
        header_layout.addStretch()
        header_layout.addWidget(btn_back)

        # Scroll area for files
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setStyleSheet("""
            QScrollArea {
                border: none;
                background: transparent;
            }
        """)

        # Container for file cards
        files_container = QWidget()
        files_layout = QVBoxLayout(files_container)
        files_layout.setSpacing(10)
        files_layout.setAlignment(Qt.AlignTop)

        scroll_area.setWidget(files_container)

        layout.addWidget(header)
        layout.addWidget(scroll_area)

        self.archive_stats_label = stats_label
        self.archive_files_container = files_container
        self.archive_files_layout = files_layout

        return widget

    def create_animations(self):
        """Create shake animation for incorrect PIN."""
        self.shake_animation = QPropertyAnimation(self.pin_input, b"geometry")
        self.shake_animation.setDuration(500)
        self.shake_animation.setEasingCurve(QEasingCurve.Type.InOutBounce)

        def update_shake_keyframes():
            pos = self.pin_input.geometry()
            self.shake_animation.setKeyValueAt(0.0, QRect(pos.x() - 10, pos.y(), pos.width(), pos.height()))
            self.shake_animation.setKeyValueAt(0.1, QRect(pos.x() + 10, pos.y(), pos.width(), pos.height()))
            self.shake_animation.setKeyValueAt(0.2, QRect(pos.x() - 10, pos.y(), pos.width(), pos.height()))
            self.shake_animation.setKeyValueAt(0.3, QRect(pos.x() + 10, pos.y(), pos.width(), pos.height()))
            self.shake_animation.setKeyValueAt(0.4, QRect(pos.x() - 10, pos.y(), pos.width(), pos.height()))
            self.shake_animation.setKeyValueAt(0.5, QRect(pos.x() + 10, pos.y(), pos.width(), pos.height()))
            self.shake_animation.setKeyValueAt(0.6, QRect(pos.x() - 10, pos.y(), pos.width(), pos.height()))
            self.shake_animation.setKeyValueAt(0.7, QRect(pos.x() + 10, pos.y(), pos.width(), pos.height()))
            self.shake_animation.setKeyValueAt(0.8, QRect(pos.x() - 10, pos.y(), pos.width(), pos.height()))
            self.shake_animation.setKeyValueAt(0.9, QRect(pos.x() + 10, pos.y(), pos.width(), pos.height()))
            self.shake_animation.setKeyValueAt(1.0, QRect(pos.x(), pos.y(), pos.width(), pos.height()))

        self.update_shake_keyframes = update_shake_keyframes

    def add_close_button(self):
        """Add close button to window"""
        self.close_btn = QPushButton("✕", self)
        self.close_btn.resize(28, 28)
        self.close_btn.move(self.width() - self.close_btn.width() - 15, 15)
        self.close_btn.clicked.connect(self.close)
        self.close_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {CLOSE_BTN_BG};
                border-radius: 14px; 
                border: none; color: {TEXT_COLOR};
                font-size: 14px; font-weight: bold; padding-bottom: 1px;
            }}
            QPushButton:hover {{ background-color: {CLOSE_BTN_HOVER}; }}
            QPushButton:pressed {{ background-color: {CLOSE_BTN_PRESSED}; }}
        """)
        self.close_btn.raise_()

    def setup_backend_thread(self):
        """Setup the worker thread for vault operations."""
        self.thread = QThread()
        self.manager = VaultProcessManager()
        self.manager.moveToThread(self.thread)

        # Connect signals
        self.manager.status_updated.connect(self.on_status_update)
        self.manager.usb_detected.connect(self.on_usb_detected)
        self.manager.pin_verified.connect(self.on_pin_verified)
        self.manager.pin_incorrect.connect(self.on_pin_incorrect)
        self.manager.vault_mounted.connect(self.on_vault_mounted)
        self.manager.vault_locked.connect(self.on_vault_locked)

        self.thread.started.connect(self.manager.run)
        self.thread.start()

    # ==================== ACTION HANDLERS ====================

    @Slot()
    def verify_pin(self):
        """Verify PIN and proceed to main menu"""
        pin = self.pin_input.text()
        if not pin:
            return

        self.pin_status.setText("Verifying PIN...")
        self.pin_status.setStyleSheet(f"color: {TEXT_COLOR}; background: transparent;")
        self.pin_input.setEnabled(False)

        # Verify PIN in manager
        self.manager.verify_pin(pin)

    @Slot()
    def open_vault_action(self):
        """Open vault and mount files"""
        self.manager.mount_vault()

    @Slot()
    def view_logs_action(self):
        """Load and display logs"""
        self.log_display.setText("Loading logs...")
        self.stacked_widget.setCurrentIndex(4)  # Go to log viewer screen

        # Load logs
        log_viewer = LogViewerManager(self.manager.usb_root, self.manager.key)
        log_viewer.logs_loaded.connect(self.display_logs)
        log_viewer.error_occurred.connect(self.on_logs_error)
        log_viewer.load_logs()

    @Slot()
    def lock_vault_action(self):
        """Lock vault and return to menu"""
        self.manager.lock_vault()

    @Slot()
    def reset_pin_action(self):
        """Show PIN reset screen"""
        self.stacked_widget.setCurrentIndex(5)  # Go to PIN reset screen
        self.reset_status.setText("")
        self.reset_status.setStyleSheet(f"color: {TEXT_COLOR}; background: transparent;")
        self.reset_current_pin.clear()
        self.reset_totp.clear()
        self.reset_new_pin.clear()
        self.reset_confirm_pin.clear()
        self.reset_current_pin.setFocus()

    @Slot()
    def process_pin_reset(self):
        """Process PIN reset with 2FA verification"""
        current_pin = self.reset_current_pin.text().strip()
        totp_code = self.reset_totp.text().strip()
        new_pin = self.reset_new_pin.text().strip()
        confirm_pin = self.reset_confirm_pin.text().strip()

        # Validation
        if not all([current_pin, totp_code, new_pin, confirm_pin]):
            self.reset_status.setText("❌ All fields are required")
            self.reset_status.setStyleSheet(f"color: {ERROR_COLOR}; background: transparent;")
            return

        if len(totp_code) != 6 or not totp_code.isdigit():
            self.reset_status.setText("❌ TOTP code must be 6 digits")
            self.reset_status.setStyleSheet(f"color: {ERROR_COLOR}; background: transparent;")
            return

        if new_pin != confirm_pin:
            self.reset_status.setText("❌ New PINs don't match")
            self.reset_status.setStyleSheet(f"color: {ERROR_COLOR}; background: transparent;")
            return

        if len(new_pin) < 4:
            self.reset_status.setText("❌ PIN must be at least 4 characters")
            self.reset_status.setStyleSheet(f"color: {ERROR_COLOR}; background: transparent;")
            return

        if current_pin == new_pin:
            self.reset_status.setText("❌ New PIN must be different from current PIN")
            self.reset_status.setStyleSheet(f"color: {ERROR_COLOR}; background: transparent;")
            return

        self.reset_status.setText("⏳ Verifying...")
        self.reset_status.setStyleSheet(f"color: {TEXT_COLOR}; background: transparent;")

        # Verify current PIN
        salt, nonce, correct_pin = VaultManager.load_meta(self.manager.usb_root)
        if current_pin != correct_pin:
            self.reset_status.setText("❌ Current PIN is incorrect")
            self.reset_status.setStyleSheet(f"color: {ERROR_COLOR}; background: transparent;")
            return

        # Load and verify TOTP
        totp_secret = load_totp_secret(self.manager.usb_root, self.manager.key)
        if not totp_secret:
            self.reset_status.setText("❌ 2FA not setup for this vault")
            self.reset_status.setStyleSheet(f"color: {ERROR_COLOR}; background: transparent;")
            return

        if not verify_totp(totp_secret, totp_code):
            self.reset_status.setText("❌ Invalid 2FA code")
            self.reset_status.setStyleSheet(f"color: {ERROR_COLOR}; background: transparent;")
            return

        # Update PIN
        self.reset_status.setText("⏳ Updating PIN and re-encrypting vault...")
        success = update_pin_in_meta(self.manager.usb_root, self.manager.key, new_pin)

        if success:
            # Update manager's key to new key
            new_key = VaultManager.derive_key(new_pin, salt)
            self.manager.key = new_key
            self.vault_key = new_key

            # Log the event
            append_log(self.manager.usb_root, new_key, "PIN Reset (2FA Verified)")

            # 📱 Send notification - PIN reset
            send_telegram_notification("🔑 *PIN Changed*\nVault PIN was reset using 2FA.")

            self.reset_status.setText("✅ PIN updated successfully!")
            self.reset_status.setStyleSheet(f"color: {SUCCESS_COLOR}; background: transparent;")

            # Return to menu after 2 seconds
            QTimer.singleShot(2000, lambda: self.stacked_widget.setCurrentIndex(2))
        else:
            self.reset_status.setText("❌ Failed to update PIN")
            self.reset_status.setStyleSheet(f"color: {ERROR_COLOR}; background: transparent;")

    @Slot()
    def view_archive_action(self):
        """Show archive screen with deleted files"""
        self.stacked_widget.setCurrentIndex(6)  # Go to archive screen
        self.load_archived_files()

    def load_archived_files(self):
        """Load and display archived files"""
        try:
            # Clear existing file cards
            while self.archive_files_layout.count():
                child = self.archive_files_layout.takeAt(0)
                if child.widget():
                    child.widget().deleteLater()

            # Get archive manager
            archive_manager = ArchiveManager(self.manager.usb_root, self.manager.key)

            # Get statistics
            stats = archive_manager.get_statistics()
            self.archive_stats_label.setText(
                f"{stats['total_files']} files  •  {stats['total_size_readable']}  •  Auto-delete after 30 days"
            )

            # Get files grouped by month
            grouped_files = archive_manager.get_files_grouped_by_month()

            if not grouped_files:
                no_files_label = QLabel("No deleted files in archive.")
                no_files_label.setAlignment(Qt.AlignCenter)
                no_files_label.setStyleSheet(f"color: {TEXT_COLOR}; padding: 40px; font-size: 14px;")
                self.archive_files_layout.addWidget(no_files_label)
                return

            # Display files grouped by month
            for group in grouped_files:
                # Month header
                month_header = QLabel(f"📅 {group['month']}")
                month_header.setFont(QFont("Arial", 14, QFont.Weight.Bold))
                month_header.setStyleSheet(f"color: {TEXT_COLOR}; background: transparent; padding: 10px 0;")
                self.archive_files_layout.addWidget(month_header)

                # File cards
                for file_entry in group['files']:
                    file_card = self.create_archive_file_card(file_entry)
                    self.archive_files_layout.addWidget(file_card)

        except Exception as e:
            print(f"[Archive UI] Error loading files: {e}")
            error_label = QLabel(f"Error loading archive: {str(e)}")
            error_label.setStyleSheet(f"color: {ERROR_COLOR}; padding: 20px;")
            self.archive_files_layout.addWidget(error_label)

    def create_archive_file_card(self, file_entry):
        """Create a card widget for an archived file"""
        card = QWidget()
        card.setStyleSheet(f"""
            QWidget {{
                background-color: rgba(0, 0, 0, 0.03);
                border: 1px solid rgba(0, 0, 0, 0.1);
                border-radius: 10px;
                padding: 15px;
            }}
        """)

        layout = QVBoxLayout(card)
        layout.setSpacing(8)

        # File info row
        info_row = QWidget()
        info_layout = QHBoxLayout(info_row)
        info_layout.setContentsMargins(0, 0, 0, 0)

        # File icon and name
        filename = file_entry.get("filename", "Unknown")
        ext = os.path.splitext(filename)[1].lower()

        if ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp']:
            icon = "🖼️"
        elif ext in ['.pdf']:
            icon = "📄"
        elif ext in ['.doc', '.docx']:
            icon = "📝"
        elif ext in ['.xls', '.xlsx']:
            icon = "📊"
        elif ext in ['.zip', '.rar', '.7z']:
            icon = "📦"
        elif ext in ['.mp4', '.avi', '.mov']:
            icon = "🎥"
        elif ext in ['.mp3', '.wav', '.flac']:
            icon = "🎵"
        else:
            icon = "📄"

        file_label = QLabel(f"{icon} {filename}")
        file_label.setFont(QFont("Arial", 13, QFont.Weight.DemiBold))
        file_label.setStyleSheet(f"color: {TEXT_COLOR}; background: transparent;")

        size_label = QLabel(file_entry.get("file_size_readable", ""))
        size_label.setFont(QFont("Arial", 11))
        size_label.setStyleSheet(f"color: rgba(34, 34, 34, 0.6); background: transparent;")

        info_layout.addWidget(file_label)
        info_layout.addStretch()
        info_layout.addWidget(size_label)

        # Details row
        deleted_date = file_entry.get("deleted_date", "")
        deleted_time = file_entry.get("deleted_time", "")
        days_remaining = file_entry.get("days_remaining", 30)
        original_path = file_entry.get("original_path", "")

        details_label = QLabel(
            f"Deleted: {deleted_date} at {deleted_time}  •  "
            f"Days remaining: {days_remaining}  •  "
            f"Path: {original_path}"
        )
        details_label.setFont(QFont("Arial", 10))
        details_label.setStyleSheet(f"color: rgba(34, 34, 34, 0.5); background: transparent;")
        details_label.setWordWrap(True)

        # Buttons row
        buttons_row = QWidget()
        buttons_layout = QHBoxLayout(buttons_row)
        buttons_layout.setContentsMargins(0, 0, 0, 0)
        buttons_layout.setSpacing(8)

        btn_restore = QPushButton("🔄 Restore")
        btn_restore.setFixedHeight(35)
        btn_restore.setStyleSheet(f"""
            QPushButton {{
                background-color: {ACCENT_COLOR};
                color: white; border: none; border-radius: 6px;
                padding: 0 15px; font-size: 12px; font-weight: bold;
            }}
            QPushButton:hover {{ background-color: #0070e6; }}
        """)
        btn_restore.clicked.connect(lambda: self.restore_file_action(file_entry.get("id")))

        btn_delete = QPushButton("🗑️ Delete Forever")
        btn_delete.setFixedHeight(35)
        btn_delete.setStyleSheet(f"""
            QPushButton {{
                background-color: rgba(217, 48, 37, 0.1);
                color: {ERROR_COLOR}; border: 1px solid {ERROR_COLOR};
                border-radius: 6px; padding: 0 15px; font-size: 12px;
            }}
            QPushButton:hover {{ background-color: rgba(217, 48, 37, 0.2); }}
        """)
        btn_delete.clicked.connect(lambda: self.delete_permanently_action(file_entry.get("id"), filename))

        buttons_layout.addWidget(btn_restore)
        buttons_layout.addWidget(btn_delete)
        buttons_layout.addStretch()

        # Add all rows to card
        layout.addWidget(info_row)
        layout.addWidget(details_label)
        layout.addWidget(buttons_row)

        return card

    @Slot()
    def restore_file_action(self, file_id):
        """Restore file from archive back to vault"""
        try:
            archive_manager = ArchiveManager(self.manager.usb_root, self.manager.key)

            # Restore file
            file_data, error = archive_manager.restore_file(file_id)

            if error:
                print(f"[Archive] Restore failed: {error}")
                return

            # Add file back to vault
            vault_path = os.path.join(self.manager.usb_root, ".dll", "vault.enc")

            # Load current vault
            current_vault = self.manager.vault_manager.decrypt_vault(
                self.manager.usb_root,
                self.manager.key
            )

            # Add restored file
            current_vault["files"][file_data["path"]] = list(file_data["content"])

            # Re-encrypt vault
            self.manager.vault_manager.encrypt_vault(
                self.manager.usb_root,
                self.manager.key,
                current_vault
            )

            # Log event
            filename = os.path.basename(file_data["path"])
            append_log(self.manager.usb_root, self.manager.key, f"File Restored: {filename}")

            print(f"[Archive] File restored: {filename}")

            # Reload archive display
            self.load_archived_files()

        except Exception as e:
            print(f"[Archive] Restore error: {e}")
            import traceback
            traceback.print_exc()

    @Slot()
    def delete_permanently_action(self, file_id, filename):
        """Permanently delete file from archive"""
        # Confirmation dialog
        reply = QMessageBox.question(
            self,
            "Delete Forever",
            f"Are you sure you want to permanently delete '{filename}'?\n\n"
            "This action cannot be undone!",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            try:
                archive_manager = ArchiveManager(self.manager.usb_root, self.manager.key)
                success = archive_manager.delete_permanently(file_id)

                if success:
                    # Log event
                    append_log(self.manager.usb_root, self.manager.key, f"File Permanently Deleted: {filename}")
                    print(f"[Archive] Permanently deleted: {filename}")

                    # Reload archive display
                    self.load_archived_files()
                else:
                    print(f"[Archive] Failed to delete: {filename}")

            except Exception as e:
                print(f"[Archive] Delete error: {e}")

    def open_vault_folder(self):
        """Open the vault folder in file explorer."""
        if os.path.exists(self.temp_path):
            if sys.platform == 'win32':
                subprocess.Popen(f'explorer "{os.path.realpath(self.temp_path)}"')
            elif sys.platform == 'darwin':
                subprocess.Popen(['open', self.temp_path])
            else:
                subprocess.Popen(['xdg-open', self.temp_path])

    # ==================== SIGNAL HANDLERS ====================

    @Slot(str)
    def on_status_update(self, text):
        """Handle status updates."""
        self.detecting_status.setText(text)

    @Slot(str)
    def on_usb_detected(self, usb_path):
        """USB detected - go to PIN entry"""
        self.usb_root = usb_path
        self.stacked_widget.setCurrentIndex(1)  # Go to PIN entry screen
        self.pin_input.setFocus()

    @Slot()
    def on_pin_verified(self):
        """PIN verified - go to main menu"""
        self.vault_key = self.manager.key
        self.pin_status.setText("✅ PIN Verified!")
        QTimer.singleShot(500, lambda: self.stacked_widget.setCurrentIndex(2))  # Go to main menu

    @Slot()
    def on_pin_incorrect(self):
        """Handle incorrect PIN feedback."""
        self.update_shake_keyframes()
        self.shake_animation.start()

        self.pin_status.setText("❌ Incorrect PIN\nTry again")
        self.pin_status.setStyleSheet(f"color: {ERROR_COLOR}; background: transparent;")
        self.pin_input.setEnabled(True)
        self.pin_input.clear()
        self.pin_input.setFocus()

    @Slot(str)
    def on_vault_mounted(self, temp_path):
        """Vault mounted - go to vault open screen"""
        self.temp_path = temp_path
        self.stacked_widget.setCurrentIndex(3)  # Go to vault open screen

    @Slot()
    def on_vault_locked(self):
        """Vault locked - back to main menu"""
        self.stacked_widget.setCurrentIndex(2)  # Back to main menu

    @Slot(list)
    def display_logs(self, logs):
        """Display logs in text area"""
        if not logs:
            self.log_display.setText("No logs found.")
            return

        log_text = "===== VAULT ACCESS LOGS (Newest First) =====\n\n"

        for entry in logs:
            log_text += f"Time: {entry.get('timestamp', 'Unknown')}\n"
            log_text += f"Event: {entry.get('event', 'Unknown')}\n"
            log_text += f"PC: {entry.get('pc_name', 'Unknown')}\n"
            log_text += f"User: {entry.get('username', 'Unknown')}\n"
            log_text += f"MAC: {entry.get('mac', 'Unknown')}\n"
            log_text += f"OS: {entry.get('os_name', 'Unknown')} {entry.get('os_version', '')}\n"
            log_text += f"CPU: {entry.get('cpu', 'Unknown')}\n"
            log_text += f"RAM: {entry.get('ram_gb', 'Unknown')} GB\n"
            log_text += "-" * 60 + "\n\n"

        self.log_display.setText(log_text)

    @Slot(str)
    def on_logs_error(self, error):
        """Handle log loading errors"""
        self.log_display.setText(f"Error loading logs:\n{error}")

    # ==================== WINDOW MANAGEMENT ====================

    def mousePressEvent(self, event):
        """Handle mouse press for window dragging."""
        if event.button() == Qt.LeftButton:
            if self.childAt(event.position().toPoint()) is None:
                self.drag_pos = event.globalPosition().toPoint()

    def mouseMoveEvent(self, event):
        """Handle mouse move for window dragging."""
        if self.drag_pos:
            self.move(self.pos() + event.globalPosition().toPoint() - self.drag_pos)
            self.drag_pos = event.globalPosition().toPoint()

    def mouseReleaseEvent(self, event):
        """Handle mouse release."""
        self.drag_pos = None

    def paintEvent(self, event):
        """Draw glass morphism background."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setBrush(GLASS_COLOR)
        painter.setPen(Qt.NoPen)
        painter.drawRoundedRect(self.rect(), 25, 25)

        border_color = QColor(255, 255, 255, 120)
        painter.setPen(border_color)
        painter.setBrush(Qt.NoBrush)
        painter.drawRoundedRect(self.rect().adjusted(0, 0, -1, -1), 25, 25)

    def closeEvent(self, event):
        """Clean up on window close."""
        self.manager.stop()
        self.thread.quit()
        self.thread.wait()
        super().closeEvent(event)


def main():
    """Main entry point for the application."""
    app = QApplication(sys.argv)
    window = GlassWindow()
    window.show()
    sys.exit(app.exec())


# ==================== CRITICAL GUARD ====================
if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
