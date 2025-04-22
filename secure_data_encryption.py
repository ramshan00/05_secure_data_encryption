import streamlit as st
import hashlib, base64, json, os, time
from cryptography.fernet import Fernet

DATA_FILE = "secure_data.json"

# Load & Save data
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

# PBKDF2 hashing
def hash_passkey(passkey, salt="salt"):
    key = hashlib.pbkdf2_hmac('sha256', passkey.encode(), salt.encode(), 100000)
    return base64.b64encode(key).decode()

# Fernet key (stored in memory for demo)
FERNET_KEY = Fernet.generate_key()
cipher = Fernet(FERNET_KEY)

# Encrypt / Decrypt
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(token):
    return cipher.decrypt(token.encode()).decode()

# Session state
st.session_state.setdefault("user", None)
st.session_state.setdefault("failed_attempts", 0)
st.session_state.setdefault("lockout_time", 0)

# Load DB
db = load_data()

# UI
st.title("🔐 Secure Multi-User Data Locker")

# Auth section
if not st.session_state.user:
    tab1, tab2 = st.tabs(["🔑 Login", "📝 Register"])

    with tab1:
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.button("Login"):
            if username in db and db[username]["password"] == hash_passkey(password):
                st.session_state.user = username
                st.session_state.failed_attempts = 0
                st.success(f"Welcome back, {username}!")
            else:
                st.session_state.failed_attempts += 1
                if st.session_state.failed_attempts >= 3:
                    st.session_state.lockout_time = time.time() + 60
                    st.warning("⏳ Too many attempts! Try again in 1 minute.")
                else:
                    st.error(f"❌ Invalid credentials. Attempts left: {3 - st.session_state.failed_attempts}")

    with tab2:
        new_user = st.text_input("New Username")
        new_pass = st.text_input("New Password", type="password")
        if st.button("Register"):
            if new_user in db:
                st.error("⚠️ Username already exists.")
            else:
                db[new_user] = {
                    "password": hash_passkey(new_pass),
                    "data": []
                }
                save_data(db)
                st.success("✅ Registration complete! Please login.")

# Logged-in area
else:
    if time.time() < st.session_state.lockout_time:
        st.warning("🔒 You are locked out. Please wait...")
        st.stop()

    st.sidebar.success(f"Logged in as {st.session_state.user}")
    st.sidebar.button("Logout", on_click=lambda: st.session_state.update(user=None))

    action = st.selectbox("Select Action", ["Store Data", "Retrieve Data"])

    if action == "Store Data":
        raw_data = st.text_area("Enter Data to Encrypt")
        passkey = st.text_input("Encryption Passkey", type="password")
        if st.button("Encrypt & Save"):
            if raw_data and passkey:
                encrypted_text = encrypt_data(raw_data)
                hashed_pass = hash_passkey(passkey)
                db[st.session_state.user]["data"].append({
                    "encrypted_text": encrypted_text,
                    "passkey": hashed_pass
                })
                save_data(db)
                st.success("🔐 Data saved securely!")
            else:
                st.error("❗ Please provide both fields.")

    elif action == "Retrieve Data":
        options = db[st.session_state.user]["data"]
        if options:
            selected = st.selectbox("Select Encrypted Entry", options, format_func=lambda x: x["encrypted_text"][:30] + "...")
            passkey = st.text_input("Enter Passkey to Decrypt", type="password")
            if st.button("Decrypt"):
                hashed_pass = hash_passkey(passkey)
                if selected["passkey"] == hashed_pass:
                    decrypted = decrypt_data(selected["encrypted_text"])
                    st.success(f"✅ Decrypted Data:\n{decrypted}")
                    st.session_state.failed_attempts = 0
                else:
                    st.session_state.failed_attempts += 1
                    if st.session_state.failed_attempts >= 3:
                        st.session_state.lockout_time = time.time() + 60
                        st.warning("⏳ Locked out for 1 minute due to failed attempts.")
                    else:
                        st.error(f"❌ Wrong passkey. Attempts left: {3 - st.session_state.failed_attempts}")
        else:
            st.info("ℹ️ No data stored yet.")

# Footer
st.markdown(
    """
    <hr style="margin-top: 3rem;"/>
    <div style="text-align: center; color: gray; font-size: 0.9rem;">
        © 2025 <strong>Ramsha Noshad</strong>
    </div>
    """,
    unsafe_allow_html=True
)
