import os
import json
import getpass
import shutil
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from log_manager import append_log


# ---------------------------
# CONFIG
# ---------------------------
USB_ROOT = None
VAULT_DIR_NAME = ".dll"
META_FILE = "meta.key"
VAULT_FILE = "vault.enc"
TEMP_VAULT = r"C:\USBVaultTemp"


# ---------------------------
# DETECT USB
# ---------------------------
def detect_usb():
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        check_path = f"{letter}:\\{VAULT_DIR_NAME}\\{META_FILE}"
        if os.path.exists(check_path):
            return letter + ":"
    return None


# ---------------------------
# LOAD META
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
# DERIVE KEY
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
# DECRYPT VAULT
# ---------------------------
def decrypt_vault(usb_path, key):
    vault_path = os.path.join(usb_path, VAULT_DIR_NAME, VAULT_FILE)
    meta_path = os.path.join(usb_path, VAULT_DIR_NAME, META_FILE)

    with open(vault_path, "rb") as f:
        ct = f.read()
    with open(meta_path, "rb") as f:
        meta = f.read()

    nonce = meta[16:28]

    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ct, None)
    return json.loads(plaintext.decode())


# ---------------------------
# ENCRYPT VAULT
# ---------------------------
def encrypt_vault(usb_path, key, data):
    import secrets

    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)

    ct = aesgcm.encrypt(nonce, json.dumps(data).encode(), None)

    vault_path = os.path.join(usb_path, VAULT_DIR_NAME, VAULT_FILE)
    meta_path = os.path.join(usb_path, VAULT_DIR_NAME, META_FILE)

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


# ---------------------------
# MAIN
# ---------------------------
def main():
    global USB_ROOT
    print("Detecting secure USB...")

    USB_ROOT = detect_usb()
    if USB_ROOT is None:
        print("❌ Secure USB not detected.")
        return

    print(f"✔ USB found at {USB_ROOT}")

    salt, nonce, correct_pin = load_meta(USB_ROOT)

    print("Enter PIN:")
    user_pin = input().strip()
    if user_pin != correct_pin:
        print("❌ Incorrect PIN.")
        return

    print("✔ PIN verified")

    key = derive_key(user_pin, salt)

    # Create temp folder
    if os.path.exists(TEMP_VAULT):
        shutil.rmtree(TEMP_VAULT)
    os.makedirs(TEMP_VAULT, exist_ok=True)

    # Decrypt vault
    data = decrypt_vault(USB_ROOT, key)
    print("✔ Vault decrypted")

    # ---------- FIXED ARG ORDER ----------
    append_log(USB_ROOT, key, "Vault Opened")

    # Extract decrypted files to TEMP
    for name, content in data["files"].items():
        file_path = os.path.join(TEMP_VAULT, name)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)

        with open(file_path, "wb") as f:
            f.write(bytes(content))

    print(f"Vault opened at: {TEMP_VAULT}")
    input("Press ENTER when done editing files...")

    # Rebuild vault
    new_data = {"files": {}}

    for root, dirs, files in os.walk(TEMP_VAULT):
        for file in files:
            p = os.path.join(root, file)
            rel_path = os.path.relpath(p, TEMP_VAULT)

            with open(p, "rb") as f:
                new_data["files"][rel_path] = list(f.read())

    encrypt_vault(USB_ROOT, key, new_data)
    shutil.rmtree(TEMP_VAULT)

    print("✔ Vault re-encrypted and temp removed.")

    # ---------- FIXED ARG ORDER ----------
    append_log(USB_ROOT, key, "Vault Closed")


if __name__ == "__main__":
    main()
