import os
import json
import getpass
import secrets
import pyotp
import qrcode
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# ---------------------------
# CONFIG
# ---------------------------
def get_usb_path():
    drive = input("Enter your USB drive letter (example: E): ").strip().upper()
    return f"{drive}:\\.dll"

USB_PATH = get_usb_path()
 # USB path to store vault
VAULT_FILE = "vault.enc"
META_FILE = "meta.key"
TOTP_FILE = "totp.enc"  # NEW: Store TOTP secret


# ---------------------------
# CREATE VAULT WITH 2FA
# ---------------------------
def create_vault():
    print("\n" + "=" * 60)
    print("       USB VAULT CREATION WITH 2FA (Google Authenticator)")
    print("=" * 60 + "\n")

    # Check if vault directory exists, if not create it
    if not os.path.exists(USB_PATH):
        try:
            os.makedirs(USB_PATH)
            print(f"✔ Created vault directory: {USB_PATH}")
        except Exception as e:
            print(f"❌ Error creating directory: {e}")
            return

    # Ask user for PIN
    print("STEP 1: Set Your Vault PIN")
    print("-" * 60)
    pin = getpass.getpass("Set a PIN for your vault: ").strip()

    if not pin:
        print("❌ PIN cannot be empty. Exiting.")
        return

    pin_confirm = getpass.getpass("Confirm PIN: ").strip()

    if pin != pin_confirm:
        print("❌ PINs do not match. Exiting.")
        return

    print("✔ PIN set successfully!\n")

    # Generate TOTP secret for 2FA
    print("STEP 2: Setup Two-Factor Authentication (2FA)")
    print("-" * 60)
    print("Generating 2FA secret key...")

    totp_secret = pyotp.random_base32()
    totp = pyotp.TOTP(totp_secret)

    # Generate QR code for Google Authenticator
    provisioning_uri = totp.provisioning_uri(
        name="USB Vault",
        issuer_name="SecureUSB"
    )

    # Create QR code
    print("Creating QR code for Google Authenticator...")
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=5
    )
    qr.add_data(provisioning_uri)
    qr.make(fit=True)

    # Save QR code image
    qr_path = os.path.join(USB_PATH, "totp_setup.png")
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(qr_path)

    print(f"✔ QR Code saved at: {qr_path}\n")

    print("=" * 60)
    print("📱 GOOGLE AUTHENTICATOR SETUP INSTRUCTIONS:")
    print("=" * 60)
    print("1. Install Google Authenticator app on your phone")
    print("   - Android: Play Store")
    print("   - iOS: App Store")
    print("")
    print("2. Open Google Authenticator app")
    print("")
    print("3. Tap '+' or 'Add account' button")
    print("")
    print("4. Select 'Scan a QR code'")
    print("")
    print(f"5. Scan the QR code image saved on your USB drive:")
    print(f"   {qr_path}")
    print("")
    print("6. Your vault will appear as:")
    print("   📱 USB Vault (SecureUSB)")
    print("")
    print("=" * 60)
    print("⚠️  IMPORTANT - BACKUP YOUR SECRET KEY:")
    print("=" * 60)
    print("If you lose your phone, you can recover 2FA using this key:")
    print(f"\n   🔑 SECRET KEY: {totp_secret}\n")
    print("⚠️  Write this down and store it in a safe place!")
    print("⚠️  Do NOT share this key with anyone!")
    print("=" * 60 + "\n")

    input("Press ENTER after you've scanned the QR code with Google Authenticator...")

    # Verify TOTP works
    print("\nSTEP 3: Verify 2FA Setup")
    print("-" * 60)
    print("Please enter the 6-digit code from Google Authenticator app")
    print("(The code changes every 30 seconds)\n")

    max_attempts = 3
    for attempt in range(max_attempts):
        otp = input(f"Enter 6-digit code (Attempt {attempt + 1}/{max_attempts}): ").strip()

        if not otp:
            print("❌ Code cannot be empty. Try again.\n")
            continue

        if len(otp) != 6 or not otp.isdigit():
            print("❌ Invalid format. Code must be exactly 6 digits. Try again.\n")
            continue

        if totp.verify(otp, valid_window=1):
            print("✔ 2FA verified successfully!\n")
            break
        else:
            if attempt < max_attempts - 1:
                print("❌ Invalid code. Please check Google Authenticator and try again.\n")
            else:
                print("❌ Too many failed attempts. Please restart setup.")
                return

    print("STEP 4: Creating Encrypted Vault")
    print("-" * 60)

    # Generate salt and nonce
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)

    # Derive key from PIN
    print("Deriving encryption key from PIN...")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000
    )
    key = kdf.derive(pin.encode())

    # Create empty vault
    print("Creating encrypted vault...")
    data = {"files": {}}
    plaintext = json.dumps(data).encode()
    aes = AESGCM(key)
    ciphertext = aes.encrypt(nonce, plaintext, None)

    # Write vault file
    vault_path = os.path.join(USB_PATH, VAULT_FILE)
    with open(vault_path, "wb") as f:
        f.write(ciphertext)
    print(f"✔ Vault created: {vault_path}")

    # Write metadata (salt + nonce + pin length + pin)
    print("Saving vault metadata...")
    meta = salt + nonce + bytes([len(pin)]) + pin.encode()
    meta_path = os.path.join(USB_PATH, META_FILE)
    with open(meta_path, "wb") as f:
        f.write(meta)
    print(f"✔ Metadata saved: {meta_path}")

    # Encrypt and save TOTP secret
    print("Encrypting 2FA secret...")
    totp_nonce = secrets.token_bytes(12)
    totp_ciphertext = aes.encrypt(totp_nonce, totp_secret.encode(), None)
    totp_path = os.path.join(USB_PATH, TOTP_FILE)
    with open(totp_path, "wb") as f:
        f.write(totp_nonce + totp_ciphertext)
    print(f"✔ 2FA secret saved: {totp_path}\n")

    print("=" * 60)
    print("✅ VAULT CREATED SUCCESSFULLY!")
    print("=" * 60)
    print("\n📂 Vault Files Created:")
    print(f"   • {vault_path}")
    print(f"   • {meta_path}")
    print(f"   • {totp_path}")
    print(f"   • {qr_path} (can delete after scanning)")
    print("\n🔐 Security Features Enabled:")
    print("   • AES-256 Encryption")
    print("   • PBKDF2 Key Derivation (200,000 iterations)")
    print("   • Two-Factor Authentication (TOTP)")
    print("\n📱 Next Steps:")
    print("   1. Keep your USB drive safe")
    print("   2. Remember your PIN")
    print("   3. Keep your phone with Google Authenticator")
    print("   4. Backup the secret key shown above")
    print("\n⚠️  Important:")
    print("   • 2FA is ONLY required for PIN reset")
    print("   • Normal vault access requires PIN only")
    print("   • Keep your backup secret key safe!")
    print("\n" + "=" * 60 + "\n")


if __name__ == "__main__":
    try:
        create_vault()
    except KeyboardInterrupt:
        print("\n\n❌ Setup cancelled by user.")
    except Exception as e:
        print(f"\n❌ Error during vault creation: {e}")
        import traceback

        traceback.print_exc()
