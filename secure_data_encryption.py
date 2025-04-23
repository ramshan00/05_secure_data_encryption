import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import time

st.set_page_config(page_title="Secure Data System", page_icon="🛡", layout="centered")

KEY = Fernet.generate_key()
cipher = Fernet(KEY)

if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

#functions
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text, passkey):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)
    for key, value in st.session_state.stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
    st.session_state.failed_attempts += 1
    return None

def reset_attempts():
    st.session_state.failed_attempts = 0

st.markdown("<h1 style='text-align:center;'>🔐 Secure Data Encryption System</h1>", unsafe_allow_html=True)

# Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("🔽 Navigation", menu)

# Pages
if choice == "Home":
    st.subheader("🏠 Welcome to Secure System")
    st.write("Encrypt your messages and store them safely!")
    st.markdown("""
    ### Features:
    - *Streamlit UI*
    - *Fernet Encryption*
    - *Hashed Passkeys*
    - *Session State Lockout*
    - *Login to Reset Attempts*
    """)
    st.info("Navigate using sidebar to begin using the app.")
    st.snow()

elif choice == "Store Data":
    st.subheader("📁 Store Secure Data")
    user_data = st.text_area("Enter Text to Encrypt")
    passkey = st.text_input("Enter Passkey", type="password")

    if st.button("🔐 Encrypt & Save"):
        if user_data and passkey:
            hashed = hash_passkey(passkey)
            encrypted = encrypt_data(user_data, passkey)
            st.session_state.stored_data[encrypted] = {"encrypted_text": encrypted, "passkey": hashed}
            st.success("✅ Data stored securely!")
            st.code(encrypted, language="text")
            st.balloons()
        else:
            st.warning("Please enter both text and passkey.")

    if st.button("⬅ Back to Home"):
        st.experimental_rerun()

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Encrypted Data")
    encrypted_input = st.text_area("Paste Encrypted Text")
    passkey_input = st.text_input("Enter Passkey", type="password")

    if st.button("🔓 Decrypt"):
        if encrypted_input and passkey_input:
            result = decrypt_data(encrypted_input, passkey_input)
            if result:
                st.success("✅ Decryption Successful!")
                st.code(result, language="text")
            else:
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts left: {remaining}")
                if st.session_state.failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts! Please login.")
                    time.sleep(2)
                    st.experimental_set_query_params(page="Login")
                    st.experimental_rerun()
        else:
            st.warning("Enter both encrypted data and passkey.")

    if st.button("⬅ Back to Home"):
        st.experimental_rerun()

elif choice == "Login":
    st.subheader("🔑 Reauthorization")
    login_pass = st.text_input("Enter Admin Password", type="password")

    if st.button("Login"):
        if login_pass == "admin123":
            reset_attempts()
            st.success("✅ Login successful! Attempts reset.")
            st.balloons()
        else:
            st.error("❌ Incorrect admin password.")

    if st.button("⬅ Back to Home"):
        st.experimental_rerun()

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
