import streamlit as st
import hashlib, json, os, time
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
import base64

# ---------------- Key Handling ----------------
KEY_FILE = "secret.key"

def load_key():
    if not os.path.exists(KEY_FILE):
        with open(KEY_FILE, "wb") as f:
            f.write(Fernet.generate_key())
    with open(KEY_FILE, "rb") as f:
        return f.read()

KEY = load_key()
cipher = Fernet(KEY)

# ---------------- File Paths ----------------
DATA_FILE = "data_store.json"
USER_FILE = "users.json"

# ---------------- Load/Save Utilities ----------------
def load_json(file, default={}):
    if not os.path.exists(file):
        return default
    with open(file, "r") as f:
        return json.load(f)

def save_json(file, data):
    with open(file, "w") as f:
        json.dump(data, f, indent=2)

stored_data = load_json(DATA_FILE)
user_db = load_json(USER_FILE)

# ---------------- Security Functions ----------------
def hash_passkey(passkey, salt):
    return base64.b64encode(hashlib.pbkdf2_hmac('sha256', passkey.encode(), salt.encode(), 100000)).decode()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# ---------------- Session State ----------------
if "user" not in st.session_state:
    st.session_state.user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = None

# ---------------- Auth System ----------------
def login(username, password):
    user = user_db.get(username)
    if not user:
        return False
    hashed = hash_passkey(password, username)
    return user["password"] == hashed

def register_user(username, password):
    if username in user_db:
        return False
    hashed = hash_passkey(password, username)
    user_db[username] = {"password": hashed}
    save_json(USER_FILE, user_db)
    return True

# ---------------- App Logic ----------------
st.title("🔐 Secure Multi-User Data System")

menu = ["Login", "Register", "Home", "Store Data", "Retrieve Data", "Logout"]
choice = st.sidebar.selectbox("Navigation", menu)

# Login
if choice == "Login":
    st.subheader("🔑 Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if login(username, password):
            st.session_state.user = username
            st.session_state.failed_attempts = 0
            st.session_state.lockout_time = None
            st.success("✅ Logged in!")
        else:
            st.error("❌ Invalid credentials")

# Register
elif choice == "Register":
    st.subheader("📝 Register")
    new_user = st.text_input("Choose a username")
    new_pass = st.text_input("Choose a password", type="password")
    if st.button("Register"):
        if register_user(new_user, new_pass):
            st.success("✅ Account created! You can now log in.")
        else:
            st.error("❌ Username already exists.")

# Home
elif choice == "Home":
    st.subheader("🏠 Home")
    if st.session_state.user:
        st.success(f"Logged in as: {st.session_state.user}")
        st.write("Use the sidebar to store or retrieve your data.")
    else:
        st.warning("Please login first.")

# Store Data
elif choice == "Store Data":
    if not st.session_state.user:
        st.warning("🔒 Please log in to store data.")
        st.stop()

    st.subheader("📂 Store Your Data")
    text = st.text_area("Enter text to encrypt")
    passkey = st.text_input("Enter passkey", type="password")

    if st.button("Encrypt & Save"):
        if text and passkey:
            user = st.session_state.user
            hashed_key = hash_passkey(passkey, user)
            encrypted = encrypt_data(text)
            stored_data[encrypted] = {"user": user, "passkey": hashed_key}
            save_json(DATA_FILE, stored_data)
            st.success("✅ Data encrypted and saved!")
            st.code(encrypted)
        else:
            st.error("⚠️ All fields required")

# Retrieve Data
elif choice == "Retrieve Data":
    if not st.session_state.user:
        st.warning("🔒 Please log in to retrieve data.")
        st.stop()

    st.subheader("🔍 Retrieve Your Data")

    # Lockout check
    if st.session_state.failed_attempts >= 3:
        if st.session_state.lockout_time is None:
            st.session_state.lockout_time = datetime.now()
        time_passed = datetime.now() - st.session_state.lockout_time
        if time_passed < timedelta(seconds=30):
            remaining = 30 - time_passed.seconds
            st.error(f"⏳ Too many attempts. Try again in {remaining} seconds.")
            st.stop()
        else:
            st.session_state.failed_attempts = 0
            st.session_state.lockout_time = None

    encrypted_text = st.text_area("Paste Encrypted Data")
    passkey = st.text_input("Enter your passkey", type="password")

    if st.button("Decrypt"):
        record = stored_data.get(encrypted_text)
        if record and record["user"] == st.session_state.user:
            hashed_key = hash_passkey(passkey, st.session_state.user)
            if hashed_key == record["passkey"]:
                st.success("✅ Data Decrypted:")
                st.code(decrypt_data(encrypted_text))
                st.session_state.failed_attempts = 0
            else:
                st.session_state.failed_attempts += 1
                st.error(f"❌ Incorrect passkey. Attempts left: {3 - st.session_state.failed_attempts}")
        else:
            st.error("❌ Data not found or not yours.")

# Logout
elif choice == "Logout":
    st.session_state.user = None
    st.success("👋 Logged out successfully.")
