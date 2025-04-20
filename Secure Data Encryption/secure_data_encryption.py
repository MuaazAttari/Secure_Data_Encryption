import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# === DATA INFORMATION OF USER ===
DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"  # Use a secure random salt in production
LOCKOUT_DURATION = 60  # seconds

# === SESSION STATE INITIALIZATION ===
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# === FILE OPERATIONS ===
def load_data():
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {}
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

# === CRYPTOGRAPHIC UTILITIES ===
def generate_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

def encrypt_text(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

stored_data = load_data()

# === UI ===
st.title("🔐 Secure Data Encryption")
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Select an option", menu)

# === HOME ===
if choice == "Home":
    st.subheader("Welcome to Secure Data Encryption")
    st.write("This app lets you securely encrypt and decrypt data using a passkey.")
    st.markdown("""
    **Note:** This is a basic prototype and not for production use.  
    Always use stronger encryption & storage methods in real-world apps.
    """)

# === REGISTER ===
elif choice == "Register":
    st.subheader("🖋️ Register New User")
    username = st.text_input("Choose a username")
    password = st.text_input("Choose a password", type="password")

    if st.button("Register"):
        if not username or not password:
            st.error("❌ Please fill in all fields!")
        elif username in stored_data:
            st.warning("⚠️ User already exists!")
        else:
            stored_data[username] = {
                "password": hash_password(password),
                "data": []
            }
            save_data(stored_data)
            st.success("✅ User registered successfully!")

# === LOGIN ===
elif choice == "Login":
    st.subheader("🔐 Login")

    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"❌ Too many failed attempts. Try again in {remaining} seconds.")
        st.stop()

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username in stored_data and stored_data[username]["password"] == hash_password(password):
            st.session_state.authenticated_user = username
            st.success("✅ Login successful!")
            st.session_state.failed_attempts = 0
        else:
            st.session_state.failed_attempts += 1
            remaining = 3 - st.session_state.failed_attempts
            st.error(f"❌ Invalid credentials. {remaining} attempts left.")

            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.error(f"❌ Too many failed attempts. Locked out for {LOCKOUT_DURATION} seconds.")
                st.stop()

# === STORE DATA ===
elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.error("❌ Please login to store data.")
    else:
        st.subheader("📦 Store Encrypted Data")
        data = st.text_area("Enter data to store")
        passkey = st.text_input("Enter passkey", type="password")

        if st.button("Encrypt And Save"):
            if data and passkey:
                encrypted = encrypt_text(data, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                save_data(stored_data)
                st.success("✅ Data encrypted and stored successfully!")
            else:
                st.error("❌ Please fill in all fields!")

# === RETRIEVE DATA ===
elif choice == "Retrieve Data":
    if not st.session_state.authenticated_user:
        st.error("🔐 Please login first.")
    else:
        st.subheader("📜 Retrieve Encrypted Data")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data:
            st.info("No data found for the user.")
        else:
            st.write("🔒 Encrypted Data Entries:")
            for i, item in enumerate(user_data):
                st.code(item, language="plaintext")

        encrypt_input = st.text_area("Paste encrypted text")
        passkey = st.text_input("Enter passkey", type="password")

        if st.button("Decrypt"):
            result = decrypt_text(encrypt_input, passkey)
            if result:
                st.success("✅ Decryption successful!")
                st.text_area("Decrypted Text", result, height=150)
            else:
                st.error("❌ Decryption failed. Check passkey or encrypted text.")
