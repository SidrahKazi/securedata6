import streamlit as st 
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# data information user

DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60


# section login details

if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None

if "failed_login_attempts" not in st.session_state:
    st.session_state.failed_login_attempts = 0

if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

    # if data is load

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

        def generate_key(passkey):
            key = pbkdf2_hmac(
                "sha256",
                passkey.encode(),
                SALT,
                100000,
            )
            return urlsafe_b64encode(key)
        
        def hash_password(password):
            return hashlib.pbkdf2_hmac(
                'sha256',
                password.encode(),
                SALT,
                100000,
            ).hex()
        

        # cryptography.fernet

        def encrypt_text(text, passkey):
           cipher = Fernet(generate_key(passkey))
           return cipher.encrypt(text.encode()).decode()
        
        # decrypt text

        def decrypt_text(encrypted_text, passkey):
           try:
               cipher = Fernet(generate_key(passkey))
               return cipher.decrypt(encrypted_text.encode()).decode()
           except:
            return None
        
        stored_data = load_data()

        #navigation bar

        st.title("Secure Data Encryption System")
        menu = ["Home", "Login", "Register", "Store Data", "Retrieve Data"]
        choice = st.sidebar.selectbox("Navigation", menu)

        if choice == "Home":
            st.subheader("Welcome to the Secure Data Encryption System")
            st.markdown("This application allows you to securely store and retrieve data using encryption.")

            # user registration
        elif choice == "Register":
            st.subheader("New User Registration")
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            confirm_password = st.text_input("Confirm Password", type="password")

            if st.button("Register"):
                if password == confirm_password:
                    if username in stored_data:
                        st.error("Username already exists.")
                    else:
                        stored_data[username] = {
                            "password": hash_password(password),
                            "data": {}
                        }

                        save_data(stored_data)
                        st.success("User registered successfully.")
                else:
                    st.error("Passwords do not match.")

            elif choice == "Login":
                        st.subheader("User Login")

                        if time.time() < st.session_state.lockout_time:
                         remaining = int(st.session_state.lockout_time - time.time())
                         st.error(f"Too many failed attempts. Please wait {remaining} seconds.")
                         st.stop()

                        username = st.text_input("Username")
                        password = st.text_input("Password", type="password")

                        if st.button("Login"):
                            if username in stored_data:
                                if stored_data[username]["password"] == hash_password(password):
                                    st.session_state.authenticated_user = username
                                    st.session_state.failed_login_attempts = 0
                                    st.success("Login successful.")
                                else:
                                    st.session_state.failed_login_attempts += 1
                                    remaining = 3 - st.session_state.failed_login_attempts
                                    st.error(f"Incorrect password. {remaining} attempts remaining.")

                                    if st.session_state.failed_login_attempts >= 3:
                                        st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                                        st.error(f"Too many failed attempts. Please wait for 60 seconds.")
                                        st.stop()

                                        # store data
                                    elif choice == "Store Encrypt Data":
                                        if not st.session_state.authenticated_user:
                                         st.error("Please log in to store data.")
                                        else:
                                            st.subheader("Store Encrypt Data")
                                            data= st.text_area(" Enter Data to store") 
                                            passkey = st.text_input("Encryption Passkey", type="password")

                                            if st.button("Store Data"):
                                                if data and passkey:
                                                    encrypted_data = encrypt_text(data, passkey)
                                                    stored_data[st.session_state.authenticated_user]["data"]. append (encrypted_data)
                                                    save_data(stored_data)
                                                    st.success("Data stored successfully.")
                                                else:
                                                    st.error("Please enter data and passkey.")
                            

                            #data retrieval

                            elif choice == "Retrieve Data":
                                if not st.session_state.authenticated_user:
                                    st.error("Please log in to retrieve data.")
                                else:
                                    st.subheader("Retrieve Data")
                                    user.data = stored_data[st.session_state.authenticated_user]["data"]
                                   
                                    if not user.data:
                                        st.warning("No data found.")
                                    else:
                                     st.write("Stored Data:")
                                    for i, encrypted_data in enumerate(user.data):
                                        st.code(item, language="plaintext")

                                        encrypted_input = st.text_input("Enter encrypted data to decrypt")
                                        passkey = st.text_input("Decryption Passkey", type="password")

                                        if st.button("Decrypt Data"):
                                            result = decrypt_text(encrypted_input, passkey)
                                            if result:
                                                st.success("Decrypted Data: " + result)
                                            else:
                                                st.error("Decryption failed. Please check the passkey or data.")
                            

                                     




