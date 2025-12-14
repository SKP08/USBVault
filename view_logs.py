import os
import json
import getpass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------------------
# CONFIG
# ---------------------------
VAULT_DIR_NAME = ".dll"
META_FILE = "meta.key"
LOG_FILE = "logs.enc"


# ---------------------------
# DETECT USB (auto)
# ---------------------------
def detect_usb():
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        check_path = f"{letter}:\\{VAULT_DIR_NAME}\\{META_FILE}"
        if os.path.exists(check_path):
            return letter + ":"
    return None


# ---------------------------
# LOAD META (PIN + salt)
# ---------------------------
def load_meta(usb_path):
    path = os.path.join(usb_path, VAULT_DIR_NAME, META_FILE)
    with open(path, "rb") as f:
        content = f.read()

    salt = content[:16]
    nonce = content[16:28]
    pin_len = content[28]
    pin = content[29:29 + pin_len].decode()
    return salt, nonce, pin


# ---------------------------
# KEY DERIVATION
# ---------------------------
def derive_key(pin, salt):
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000
    )
    return kdf.derive(pin.encode())


# ---------------------------
# DECRYPT LOG FILE
# ---------------------------
def decrypt_logs(usb_path, key):
    log_path = os.path.join(usb_path, VAULT_DIR_NAME, LOG_FILE)

    if not os.path.exists(log_path):
        print("❌ No logs found.")
        return []

    with open(log_path, "rb") as f:
        data = f.read()

    nonce = data[:12]
    ciphertext = data[12:]

    aes = AESGCM(key)

    try:
        plaintext = aes.decrypt(nonce, ciphertext, None)
        return json.loads(plaintext.decode())
    except Exception:
        print("❌ Failed to decrypt logs (wrong PIN or corrupted logs).")
        return []


# ---------------------------
# MAIN
# ---------------------------
def main():
    print("Detecting USB Vault...")

    usb = detect_usb()
    if usb is None:
        print("❌ Vault USB not detected.")
        input("\nPress ENTER to close...")
        return

    print(f"✔ USB detected at {usb}")

    salt, nonce, correct_pin = load_meta(usb)

    user_pin = getpass.getpass("Enter PIN to view logs: ").strip()
    if user_pin != correct_pin:
        print("❌ Wrong PIN.")
        input("\nPress ENTER to close...")
        return

    print("✔ PIN verified.")

    key = derive_key(user_pin, salt)
    logs = decrypt_logs(usb, key)

    if not logs:
        input("\nPress ENTER to close...")
        return

    print("\n===== USB VAULT LOGS (Newest First) =====\n")

    for entry in reversed(logs):
        print(f"Time: {entry.get('timestamp', 'Unknown')}")
        print(f"PC Name: {entry.get('pc_name', 'Unknown')}")
        print(f"Username: {entry.get('username', 'Unknown')}")
        print(f"MAC: {entry.get('mac', 'Unknown')}")
        print(f"OS Name: {entry.get('os_name', 'Unknown')}")
        print(f"OS Version: {entry.get('os_version', 'Unknown')}")
        print(f"CPU: {entry.get('cpu', 'Unknown')}")
        print(f"RAM (GB): {entry.get('ram_gb', 'Unknown')}")
        print(f"Event: {entry.get('event', 'Unknown')}")
        print("-" * 40)

    input("\nPress ENTER to close...")


if __name__ == "__main__":
    main()
