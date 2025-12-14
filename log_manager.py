import os
import json
import secrets
import socket
import uuid
import platform
import getpass
import psutil
import subprocess
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

LOG_FILE = "logs.enc"
VAULT_DIR_NAME = ".dll"


# ---------------------------
# SAFE CPU FETCH (Windows/Linux FULL FIX)
# ---------------------------
def get_cpu_model():
    try:
        # Windows
        if platform.system().lower() == "windows":
            output = subprocess.check_output(
                "wmic cpu get Name", shell=True, stderr=subprocess.DEVNULL
            ).decode(errors="ignore").strip().split("\n")
            if len(output) > 1 and output[1].strip():
                return output[1].strip()
    except:
        pass

    # Linux fallback
    try:
        if os.path.exists("/proc/cpuinfo"):
            for line in open("/proc/cpuinfo"):
                if "model name" in line:
                    return line.split(":", 1)[1].strip()
    except:
        pass

    # Python fallback
    return platform.processor() or "Unknown"


# ---------------------------
# SYSTEM INFO COLLECTION (NO MORE UNKNOWN)
# ---------------------------
def get_system_info():
    # RAM safe read
    try:
        ram = round(psutil.virtual_memory().total / (1024 ** 3), 2)
    except:
        ram = "Unknown"

    # MAC address fix (correct order always)
    try:
        mac = uuid.getnode()
        mac_str = ":".join(f"{(mac >> ele) & 0xff:02x}" for ele in range(40, -1, -8))
    except:
        mac_str = "Unknown"

    return {
        "pc_name": socket.gethostname() or "Unknown",
        "username": getpass.getuser() or "Unknown",
        "mac": mac_str,
        "os_name": platform.system() or "Unknown",
        "os_version": platform.release() or "Unknown",
        "cpu": get_cpu_model(),
        "ram_gb": ram
    }


# ---------------------------
# CREATE LOG ENTRY
# ---------------------------
def create_log_entry(event):
    info = get_system_info()

    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "event": event,
        "pc_name": info["pc_name"],
        "username": info["username"],
        "mac": info["mac"],
        "os_name": info["os_name"],
        "os_version": info["os_version"],
        "cpu": info["cpu"],
        "ram_gb": info["ram_gb"]
    }

    return entry


# ---------------------------
# LOAD LOGS
# ---------------------------
def load_logs(usb_path, key):
    log_path = os.path.join(usb_path, VAULT_DIR_NAME, LOG_FILE)

    if not os.path.exists(log_path):
        return []

    with open(log_path, "rb") as f:
        data = f.read()

    nonce = data[:12]
    ciphertext = data[12:]

    aes = AESGCM(key)

    try:
        plaintext = aes.decrypt(nonce, ciphertext, None)
        return json.loads(plaintext.decode())
    except:
        return []  # return empty logs rather than crashing


# ---------------------------
# SAVE LOGS
# ---------------------------
def save_logs(usb_path, key, logs):
    log_path = os.path.join(usb_path, VAULT_DIR_NAME, LOG_FILE)

    aes = AESGCM(key)
    nonce = secrets.token_bytes(12)

    ciphertext = aes.encrypt(nonce, json.dumps(logs).encode(), None)

    with open(log_path, "wb") as f:
        f.write(nonce + ciphertext)


# ---------------------------
# APPEND LOG — FIXED ARG ORDER
# append_log(usb_path, key, event)
# ---------------------------
def append_log(usb_path, key, event):
    logs = load_logs(usb_path, key)
    logs.append(create_log_entry(event))
    save_logs(usb_path, key, logs)
