# main.py

import streamlit as st
import hashlib
import json
import os
import logging
from cryptography.fernet import Fernet

# Setup logging (for debugging purposes)
logging.basicConfig(level=logging.DEBUG)

# Constants
KEY_FILE = "secret.key"
DATA_FILE = "stored_data.json"
MASTER_PASSWORD = "admin123"

# Load or generate Fernet key
def load_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        return key

cipher = Fernet(load_or_create_key())

# Load or initialize stored data
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

stored_data = load_data()

# Session state initialization
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "authorized" not in st.session_state:
    st.session_state.authorized = True

# Utility functions
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, hashed_passkey):
    try:
        data = stored_data.get(encrypted_text)
        if data and data["passkey"] == hashed_passkey:
            return cipher.decrypt(encrypted_text.encode()).decode()
    except Exception as e:
        logging.error(f"Decryption error: {e}")
        st.error("⚠️ Decryption error. Please make sure the data is valid.")
    return None

# Streamlit UI
st.title("🔐 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data"]
if not st.session_state.authorized:
    menu = ["Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("Use this app to securely **store** and **retrieve** data with your unique passkey.")

elif choice == "Store Data":
    st.subheader("📂 Store Data")
    user_data = st.text_area("Enter Data")
    passkey = st.text_input("Enter Passkey", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data)
            stored_data[encrypted_text] = {"passkey": hashed_passkey}
            save_data(stored_data)
            st.success("✅ Data stored securely!")
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Data")
    encrypted_text = st.text_area("Enter Encrypted Data")
    passkey = st.text_input("Enter Passkey", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            hashed_passkey = hash_passkey(passkey)
            result = decrypt_data(encrypted_text, hashed_passkey)

            if result:
                st.success(f"✅ Decrypted Data: {result}")
                st.session_state.failed_attempts = 0
            else:
                st.session_state.failed_attempts += 1
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts remaining: {attempts_left}")
                if st.session_state.failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts. Please reauthorize.")
                    st.session_state.authorized = False
                  #  st.experimental_rerun()
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Login":
    st.subheader("🔑 Login Required")
    login_pass = st.text_input("Enter Master Password", type="password")
    if st.button("Login"):
        if login_pass == MASTER_PASSWORD:
            st.session_state.failed_attempts = 0
            st.session_state.authorized = True
            st.success("✅ Reauthorized successfully!")
         #   st.experimental_rerun()
        else:
            st.error("❌ Incorrect password!")
