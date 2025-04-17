import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import json
import os
from datetime import datetime, timedelta
import time
import pandas as pd

# --- Enhanced GUI Config ---
st.set_page_config(
    page_title="SecureVault Pro",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Generate or Load Encryption Key ---
def get_fernet_key():
    if 'fernet_key' not in st.session_state:
        if os.path.exists('fernet_key.key'):
            with open('fernet_key.key', 'rb') as key_file:
                st.session_state.fernet_key = key_file.read()
        else:
            st.session_state.fernet_key = Fernet.generate_key()
            with open('fernet_key.key', 'wb') as key_file:
                key_file.write(st.session_state.fernet_key)
    return st.session_state.fernet_key

cipher = Fernet(get_fernet_key())

# --- File Paths ---
USERS_FILE = 'users.json'
DATA_FILE = 'encrypted_data.json'

# --- Initialize Data Storage ---
def init_data():
    if 'stored_data' not in st.session_state:
        if os.path.exists(DATA_FILE):
            with open(DATA_FILE, 'r') as f:
                try:
                    st.session_state.stored_data = json.load(f)
                except json.JSONDecodeError:
                    st.session_state.stored_data = {}
        else:
            st.session_state.stored_data = {}
    
    if 'users' not in st.session_state:
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, 'r') as f:
                try:
                    st.session_state.users = json.load(f)
                except json.JSONDecodeError:
                    st.session_state.users = {}
        else:
            st.session_state.users = {}

# --- Save Data to File ---
def save_data():
    with open(DATA_FILE, 'w') as f:
        json.dump(st.session_state.stored_data, f)
    with open(USERS_FILE, 'w') as f:
        json.dump(st.session_state.users, f)

# --- Security Functions ---
def hash_passkey(passkey, salt=None):
    if salt is None:
        salt = os.urandom(16).hex()
    hashed = hashlib.pbkdf2_hmac('sha256', passkey.encode(), salt.encode(), 100000)
    return f"{salt}${hashed.hex()}"

def verify_password(stored_password, provided_password):
    if not stored_password or '$' not in stored_password:
        return False
    salt, hashed = stored_password.split('$')
    new_hash = hash_passkey(provided_password, salt)
    return new_hash == stored_password

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    try:
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# --- Authentication Functions ---
def register_user(username, password):
    if username in st.session_state.users:
        return False, "Username already exists"
    if len(password) < 6:
        return False, "Password must be at least 6 characters"
    
    st.session_state.users[username] = {
        'password_hash': hash_passkey(password),
        'registered_at': datetime.now().isoformat(),
        'last_login': None,
        'failed_attempts': 0,
        'locked_until': None
    }
    save_data()
    return True, "Registration successful"

def login_user(username, password):
    if username not in st.session_state.users:
        return False, "Invalid username or password"
    
    user = st.session_state.users[username]
    
    if user.get('locked_until'):
        if datetime.now() < datetime.fromisoformat(user['locked_until']):
            remaining = (datetime.fromisoformat(user['locked_until']) - datetime.now()).seconds // 60
            return False, f"Account locked. Try again in {remaining} minutes"
        else:
            user['locked_until'] = None
    
    if verify_password(user['password_hash'], password):
        user['failed_attempts'] = 0
        user['last_login'] = datetime.now().isoformat()
        st.session_state.current_user = username
        st.session_state.user_stats = {
            'encrypted_items': 0,
            'retrieved_items': 0,
            'last_activity': datetime.now().isoformat()
        }
        save_data()
        return True, "Login successful"
    else:
        user['failed_attempts'] += 1
        if user['failed_attempts'] >= 3:
            lock_time = datetime.now() + timedelta(minutes=5)
            user['locked_until'] = lock_time.isoformat()
            save_data()
            return False, "Too many failed attempts. Account locked for 5 minutes."
        save_data()
        return False, f"Invalid username or password. {3 - user['failed_attempts']} attempts remaining"

# --- Initialize App ---
init_data()

# --- Modern Glass UI CSS ---
st.markdown("""
<style>
    :root {
        --primary: #6366f1;
        --primary-dark: #4f46e5;
        --secondary: #10b981;
        --accent: #f59e0b;
        --dark: #1e293b;
        --light: #f8fafc;
        --glass: rgba(255, 255, 255, 0.2);
        --glass-border: rgba(255, 255, 255, 0.3);
    }
    
    .main {
        background: linear-gradient(135deg, #e0e7ff 0%, #c7d2fe 100%);
    }
    
    .sidebar .sidebar-content {
        background: linear-gradient(135deg, rgba(99, 102, 241, 0.9) 0%, rgba(79, 70, 229, 0.9) 100%) !important;
        backdrop-filter: blur(10px);
        -webkit-backdrop-filter: blur(10px);
        color: white;
        box-shadow: 2px 0 15px rgba(0,0,0,0.1);
        border-right: 1px solid var(--glass-border);
    }
    
    .stButton>button {
        background: linear-gradient(to right, var(--primary), var(--primary-dark));
        color: white;
        border-radius: 12px;
        padding: 0.75rem 1.75rem;
        border: none;
        font-weight: 600;
        transition: all 0.3s ease;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
    }
    
    .stButton>button:hover {
        transform: translateY(-2px);
        box-shadow: 0 7px 14px rgba(99, 102, 241, 0.3);
        background: linear-gradient(to right, var(--primary-dark), var(--primary));
    }
    
    .glass-card {
        background: var(--glass);
        backdrop-filter: blur(10px);
        -webkit-backdrop-filter: blur(10px);
        border-radius: 16px;
        padding: 25px;
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
        margin-bottom: 25px;
        border: 1px solid var(--glass-border);
        transition: all 0.3s ease;
    }
    
    .glass-card:hover {
        transform: translateY(-5px);
        box-shadow: 0 12px 28px rgba(0, 0, 0, 0.15);
    }
    
    .metric-title {
        font-size: 1rem;
        color: #4b5563;
        font-weight: 600;
        letter-spacing: 0.5px;
    }
    
    .metric-value {
        font-size: 2.5rem;
        font-weight: 700;
        color: var(--dark);
        margin: 10px 0;
        background: linear-gradient(to right, var(--primary), var(--primary-dark));
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    
    .metric-icon {
        font-size: 2rem;
        margin-bottom: 15px;
        background: linear-gradient(to right, var(--primary), var(--primary-dark));
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    
    .data-card {
        background: white;
        border-radius: 16px;
        padding: 25px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.05);
        margin-bottom: 25px;
        border: 1px solid rgba(0, 0, 0, 0.05);
        transition: all 0.3s ease;
    }
    
    .data-card:hover {
        box-shadow: 0 8px 25px rgba(0, 0, 0, 0.1);
    }
    
    .success-message {
        background: linear-gradient(to right, rgba(16, 185, 129, 0.1), rgba(16, 185, 129, 0.15));
        color: #065f46;
        padding: 18px;
        border-radius: 12px;
        margin-bottom: 25px;
        border-left: 4px solid #10b981;
        backdrop-filter: blur(5px);
    }
    
    .error-message {
        background: linear-gradient(to right, rgba(239, 68, 68, 0.1), rgba(239, 68, 68, 0.15));
        color: #b91c1c;
        padding: 18px;
        border-radius: 12px;
        margin-bottom: 25px;
        border-left: 4px solid #ef4444;
        backdrop-filter: blur(5px);
    }
    
    .warning-message {
        background: linear-gradient(to right, rgba(245, 158, 11, 0.1), rgba(245, 158, 11, 0.15));
        color: #92400e;
        padding: 18px;
        border-radius: 12px;
        margin-bottom: 25px;
        border-left: 4px solid #f59e0b;
        backdrop-filter: blur(5px);
    }
    
    .stTextInput>div>div>input, .stTextArea>div>div>textarea {
        border-radius: 12px !important;
        padding: 12px 15px !important;
        border: 1px solid #e5e7eb !important;
        background-color: rgba(255, 255, 255, 0.8) !important;
        transition: all 0.3s ease;
    }
    
    .stTextInput>div>div>input:focus, .stTextArea>div>div>textarea:focus {
        border-color: var(--primary) !important;
        box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2) !important;
        background-color: white !important;
    }
    
    .stSelectbox>div>div>select {
        border-radius: 12px !important;
        padding: 10px 12px !important;
        border: 1px solid #e5e7eb !important;
    }
    
    .logo {
        font-size: 2rem;
        font-weight: 800;
        background: linear-gradient(to right, white, #e0e7ff);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 1.5rem;
        letter-spacing: -0.5px;
    }
    
    .user-greeting {
        font-size: 1.4rem;
        color: var(--dark);
        font-weight: 600;
        margin-bottom: 0.75rem;
        letter-spacing: -0.25px;
    }
    
    .sidebar .sidebar-content .block-container {
        padding-top: 0;
    }
    
    .sidebar .sidebar-content .stSelectbox div[data-baseweb="select"] {
        background-color: rgba(255, 255, 255, 0.1);
        border-radius: 12px;
        border: 1px solid rgba(255, 255, 255, 0.2);
    }
    
    .sidebar .sidebar-content .stSelectbox div[data-baseweb="select"]:hover {
        background-color: rgba(255, 255, 255, 0.15);
    }
    
    .sidebar .sidebar-content .stSelectbox div[data-baseweb="select"] div {
        color: white;
    }
    
    .sidebar .sidebar-content .stSelectbox svg {
        fill: white;
    }
    
    .divider {
        height: 1px;
        background: linear-gradient(to right, transparent, rgba(255, 255, 255, 0.3), transparent);
        margin: 1.5rem 0;
    }
    
    /* Custom scrollbar */
    ::-webkit-scrollbar {
        width: 8px;
    }
    
    ::-webkit-scrollbar-track {
        background: rgba(0, 0, 0, 0.05);
        border-radius: 10px;
    }
    
    ::-webkit-scrollbar-thumb {
        background: rgba(99, 102, 241, 0.5);
        border-radius: 10px;
    }
    
    ::-webkit-scrollbar-thumb:hover {
        background: rgba(99, 102, 241, 0.7);
    }
</style>
""", unsafe_allow_html=True)

# --- App State Management ---
if 'current_user' not in st.session_state:
    st.session_state.current_user = None
if 'user_stats' not in st.session_state:
    st.session_state.user_stats = None
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

# --- Navigation ---
def main():
    if st.session_state.current_user is None:
        show_auth_pages()
    else:
        show_dashboard()

def show_auth_pages():
    st.sidebar.markdown('<div class="logo">SecureVault Pro</div>', unsafe_allow_html=True)
    auth_choice = st.sidebar.radio("Menu", ["Login", "Register"], label_visibility="collapsed")
    
    if auth_choice == "Login":
        st.title("🔐 Secure Sign In")
        st.markdown("Welcome back! Access your encrypted vault with your credentials.")
        
        with st.form("login_form"):
            col1, col2 = st.columns([1, 3])
            with col1:
                st.image("https://cdn-icons-png.flaticon.com/512/5087/5087579.png", width=120)
            with col2:
                username = st.text_input("Username", placeholder="Enter your username")
                password = st.text_input("Password", type="password", placeholder="Enter your password")
            
            submit = st.form_submit_button("Sign In →", type="primary")
            
            if submit:
                with st.spinner("Authenticating..."):
                    time.sleep(1)
                    success, message = login_user(username, password)
                    if success:
                        st.markdown(f'<div class="success-message">✅ {message}</div>', unsafe_allow_html=True)
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.markdown(f'<div class="error-message">❌ {message}</div>', unsafe_allow_html=True)
    
    elif auth_choice == "Register":
        st.title("🚀 Create Your Account")
        st.markdown("Join SecureVault Pro to start protecting your sensitive data.")
        
        with st.form("register_form"):
            col1, col2 = st.columns([1, 3])
            with col1:
                st.image("https://cdn-icons-png.flaticon.com/512/4400/4400628.png", width=120)
            with col2:
                username = st.text_input("Choose Username", placeholder="Pick a unique username")
                password = st.text_input("Create Password", type="password", placeholder="At least 6 characters")
                confirm_password = st.text_input("Confirm Password", type="password", placeholder="Re-enter your password")
            
            submit = st.form_submit_button("Create Account →", type="primary")
            
            if submit:
                if password != confirm_password:
                    st.markdown('<div class="error-message">❌ Passwords do not match!</div>', unsafe_allow_html=True)
                else:
                    with st.spinner("Creating your account..."):
                        time.sleep(1)
                        success, message = register_user(username, password)
                        if success:
                            st.markdown(f'<div class="success-message">✨ {message}</div>', unsafe_allow_html=True)
                            time.sleep(1)
                            st.session_state.current_user = username
                            st.session_state.user_stats = {
                                'encrypted_items': 0,
                                'retrieved_items': 0,
                                'last_activity': datetime.now().isoformat()
                            }
                            st.rerun()
                        else:
                            st.markdown(f'<div class="error-message">❌ {message}</div>', unsafe_allow_html=True)

def show_dashboard():
    st.sidebar.markdown(f"""
    <div style="margin-bottom: 2rem;">
        <div class="logo">SecureVault Pro</div>
        <div style="font-size: 1rem; color: rgba(255,255,255,0.7); margin-bottom: 1rem;">Welcome back,</div>
        <div style="font-size: 1.5rem; color: white; font-weight: 600; letter-spacing: -0.5px;">{st.session_state.current_user}</div>
        <div class="divider"></div>
    </div>
    """, unsafe_allow_html=True)
    
    menu = ["Dashboard", "🔐 Encrypt Data", "🔍 Retrieve Data", "⚙️ Account", "🚪 Logout"]
    choice = st.sidebar.selectbox("Navigation", menu, label_visibility="collapsed")
    
    if choice == "Dashboard":
        show_home_page()
    elif choice == "🔐 Encrypt Data":
        show_encrypt_page()
    elif choice == "🔍 Retrieve Data":
        show_retrieve_page()
    elif choice == "⚙️ Account":
        show_account_page()
    elif choice == "🚪 Logout":
        st.session_state.current_user = None
        st.session_state.user_stats = None
        st.rerun()

def show_home_page():
    st.title(f"📊 Dashboard")
    st.markdown(f'<div class="user-greeting">Welcome back, {st.session_state.current_user}!</div>', unsafe_allow_html=True)
    
    # Metrics
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown(f"""
        <div class="glass-card">
            <div class="metric-icon">🔐</div>
            <div class="metric-title">Encrypted Items</div>
            <div class="metric-value">{st.session_state.user_stats['encrypted_items']}</div>
            <div style="font-size: 0.9rem; color: #64748b;">Total secured data</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
        <div class="glass-card">
            <div class="metric-icon">🔍</div>
            <div class="metric-title">Retrieved Items</div>
            <div class="metric-value">{st.session_state.user_stats['retrieved_items']}</div>
            <div style="font-size: 0.9rem; color: #64748b;">Total access events</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        last_active = datetime.fromisoformat(st.session_state.user_stats['last_activity']).strftime('%b %d, %H:%M')
        st.markdown(f"""
        <div class="glass-card">
            <div class="metric-icon">⏱️</div>
            <div class="metric-title">Last Active</div>
            <div class="metric-value" style="font-size: 2rem;">{last_active}</div>
            <div style="font-size: 0.9rem; color: #64748b;">Your recent activity</div>
        </div>
        """, unsafe_allow_html=True)
    
    # Recent Activity
    st.subheader("📈 Recent Activity")
    user_data = {k: v for k, v in st.session_state.stored_data.items() 
                if 'username' in v and v['username'] == st.session_state.current_user}
    
    if user_data:
        df = pd.DataFrame.from_dict(user_data, orient='index')
        df = df[['data_name', 'created_at']]
        df['created_at'] = pd.to_datetime(df['created_at']).dt.strftime('%Y-%m-%d %H:%M')
        st.dataframe(
            df.style.set_properties(**{
                'background-color': '#ffffff',
                'border': '1px solid #e2e8f0',
                'border-radius': '12px'
            }),
            use_container_width=True,
            height=min(len(df) * 35 + 35, 400)
        )
    else:
        st.markdown("""
        <div class="glass-card">
            <div style="text-align: center; padding: 2rem;">
                <img src="https://cdn-icons-png.flaticon.com/512/4076/4076478.png" width="140" style="opacity: 0.7; margin-bottom: 1rem;">
                <h3 style="color: #4b5563; margin-bottom: 0.5rem;">No encrypted data yet</h3>
                <p style="color: #64748b;">Get started by encrypting your first piece of data</p>
                <button onclick="window.location.href='#encrypt-data'" style="
                    background: linear-gradient(to right, var(--primary), var(--primary-dark));
                    color: white;
                    border: none;
                    padding: 0.75rem 1.5rem;
                    border-radius: 12px;
                    font-weight: 600;
                    margin-top: 1rem;
                    cursor: pointer;
                    transition: all 0.3s ease;
                ">Encrypt First Data</button>
            </div>
        </div>
        """, unsafe_allow_html=True)

def show_encrypt_page():
    st.title("🔐 Encrypt New Data")
    st.markdown("Protect your sensitive information with military-grade encryption.")
    
    with st.form("encrypt_form", clear_on_submit=True):
        st.markdown("### 📝 Data Details")
        data_name = st.text_input("Data Name", placeholder="What's this data about?")
        secret_data = st.text_area("Data to Encrypt", height=200, placeholder="Enter your sensitive data here...")
        
        st.markdown("### 🔑 Security Settings")
        passkey = st.text_input("Encryption Passkey", type="password", placeholder="Create a strong passkey")
        
        submit = st.form_submit_button("🔒 Encrypt & Store →", type="primary")
        
        if submit:
            if not all([data_name, secret_data, passkey]):
                st.markdown('<div class="error-message">⚠️ All fields are required!</div>', unsafe_allow_html=True)
            else:
                with st.spinner("Encrypting your data securely..."):
                    time.sleep(1)
                    # Generate unique ID for this data
                    data_id = f"{st.session_state.current_user}_{data_name}_{datetime.now().timestamp()}"
                    
                    # Encrypt the data
                    encrypted_data = encrypt_data(secret_data)
                    hashed_passkey = hash_passkey(passkey)
                    
                    # Store the data
                    st.session_state.stored_data[data_id] = {
                        'username': st.session_state.current_user,
                        'data_name': data_name,
                        'encrypted_text': encrypted_data,
                        'passkey_hash': hashed_passkey,
                        'created_at': datetime.now().isoformat()
                    }
                    
                    # Update stats
                    st.session_state.user_stats['encrypted_items'] += 1
                    st.session_state.user_stats['last_activity'] = datetime.now().isoformat()
                    save_data()
                    
                    st.markdown("""
                    <div class="success-message">
                        <div style="display: flex; align-items: center; gap: 15px;">
                            <span style="font-size: 2rem;">✅</span>
                            <div>
                                <h3 style="margin: 0 0 5px 0;">Data encrypted successfully!</h3>
                                <p style="margin: 0; color: #047857;">Your information is now securely stored in our vault.</p>
                            </div>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    st.markdown("### Your Encrypted Data")
                    st.code(encrypted_data, language="text")
                    
                    st.markdown("""
                    <div class="warning-message">
                        <div style="display: flex; align-items: center; gap: 15px;">
                            <span style="font-size: 2rem;">⚠️</span>
                            <div>
                                <h3 style="margin: 0 0 5px 0;">Important Security Notice</h3>
                                <p style="margin: 0; color: #92400e;">Please save both the encrypted data and your passkey securely. Without both, your data cannot be recovered.</p>
                            </div>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

def show_retrieve_page():
    st.title("🔍 Retrieve Encrypted Data")
    st.markdown("Access your protected information using your passkey.")
    
    # Show user's encrypted items
    user_items = {k: v for k, v in st.session_state.stored_data.items() 
                 if 'username' in v and v['username'] == st.session_state.current_user}
    
    if not user_items:
        st.markdown("""
        <div class="glass-card">
            <div style="text-align: center; padding: 2rem;">
                <img src="https://cdn-icons-png.flaticon.com/512/4076/4076478.png" width="140" style="opacity: 0.7; margin-bottom: 1rem;">
                <h3 style="color: #4b5563; margin-bottom: 0.5rem;">No encrypted data found</h3>
                <p style="color: #64748b;">Encrypt some data first to see it here</p>
                <button onclick="window.location.href='#encrypt-data'" style="
                    background: linear-gradient(to right, var(--primary), var(--primary-dark));
                    color: white;
                    border: none;
                    padding: 0.75rem 1.5rem;
                    border-radius: 12px;
                    font-weight: 600;
                    margin-top: 1rem;
                    cursor: pointer;
                    transition: all 0.3s ease;
                ">Encrypt First Data</button>
            </div>
        </div>
        """, unsafe_allow_html=True)
        return
    
    selected_item = st.selectbox("Select data to retrieve", 
                                options=list(user_items.keys()),
                                format_func=lambda x: user_items[x]['data_name'])
    
    if selected_item:
        item = user_items[selected_item]
        
        with st.form("retrieve_form"):
            st.markdown("### 🔎 Selected Data")
            st.markdown(f"**Name:** {item['data_name']}")
            st.markdown(f"**Encrypted on:** {datetime.fromisoformat(item['created_at']).strftime('%B %d, %Y at %H:%M')}")
            
            st.markdown("### 🔑 Enter Passkey")
            passkey = st.text_input("Decryption Passkey", type="password", placeholder="Enter the passkey used for encryption")
            
            submit = st.form_submit_button("🔓 Decrypt Data →", type="primary")
            
            if submit:
                if verify_password(item['passkey_hash'], passkey):
                    with st.spinner("Decrypting your data securely..."):
                        time.sleep(1)
                        decrypted_data = decrypt_data(item['encrypted_text'])
                        if decrypted_data:
                            st.session_state.user_stats['retrieved_items'] += 1
                            st.session_state.user_stats['last_activity'] = datetime.now().isoformat()
                            save_data()
                            
                            st.markdown("""
                            <div class="success-message">
                                <div style="display: flex; align-items: center; gap: 15px;">
                                    <span style="font-size: 2rem;">✅</span>
                                    <div>
                                        <h3 style="margin: 0 0 5px 0;">Decryption successful!</h3>
                                        <p style="margin: 0; color: #047857;">Your data has been securely retrieved.</p>
                                    </div>
                                </div>
                            </div>
                            """, unsafe_allow_html=True)
                            
                            st.markdown("### Decrypted Content")
                            st.text_area("Your Data", value=decrypted_data, height=300, key="decrypted_data")
                        else:
                            st.markdown('<div class="error-message">❌ Decryption failed! Please try again.</div>', unsafe_allow_html=True)
                else:
                    st.session_state.failed_attempts += 1
                    remaining_attempts = 3 - st.session_state.failed_attempts
                    
                    if remaining_attempts > 0:
                        st.markdown(f"""
                        <div class="error-message">
                            <div style="display: flex; align-items: center; gap: 15px;">
                                <span style="font-size: 2rem;">❌</span>
                                <div>
                                    <h3 style="margin: 0 0 5px 0;">Incorrect passkey!</h3>
                                    <p style="margin: 0; color: #b91c1c;">Attempts remaining: {remaining_attempts}</p>
                                </div>
                            </div>
                        </div>
                        """, unsafe_allow_html=True)
                    else:
                        st.markdown("""
                        <div class="warning-message">
                            <div style="display: flex; align-items: center; gap: 15px;">
                                <span style="font-size: 2rem;">🔒</span>
                                <div>
                                    <h3 style="margin: 0 0 5px 0;">Too many failed attempts!</h3>
                                    <p style="margin: 0; color: #92400e;">Please log in again to continue.</p>
                                </div>
                            </div>
                        </div>
                        """, unsafe_allow_html=True)
                        time.sleep(2)
                        st.session_state.current_user = None
                        st.session_state.user_stats = None
                        st.session_state.failed_attempts = 0
                        st.rerun()

def show_account_page():
    st.title("⚙️ Account Settings")
    st.markdown("Manage your SecureVault Pro account and security settings.")
    
    user = st.session_state.users[st.session_state.current_user]
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        <div class="glass-card">
            <h3 style="color: #334155; margin-top: 0;">Account Information</h3>
            <div style="margin-bottom: 1.5rem;">
                <div style="font-size: 0.9rem; color: #64748b;">Username</div>
                <div style="font-size: 1.2rem; font-weight: 500; color: #1e293b;">{}</div>
            </div>
            <div style="margin-bottom: 1.5rem;">
                <div style="font-size: 0.9rem; color: #64748b;">Registered</div>
                <div style="font-size: 1.2rem; font-weight: 500; color: #1e293b;">{}</div>
            </div>
            <div>
                <div style="font-size: 0.9rem; color: #64748b;">Last Login</div>
                <div style="font-size: 1.2rem; font-weight: 500; color: #1e293b;">{}</div>
            </div>
        </div>
        """.format(
            st.session_state.current_user,
            datetime.fromisoformat(user['registered_at']).strftime('%B %d, %Y'),
            datetime.fromisoformat(user['last_login']).strftime('%B %d, %Y at %H:%M') if user['last_login'] else "Never"
        ), unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="glass-card">
            <h3 style="color: #334155; margin-top: 0;">Security Status</h3>
            <div style="display: flex; align-items: center; gap: 15px; margin-bottom: 1.5rem;">
                <span style="font-size: 2rem; background: linear-gradient(to right, var(--primary), var(--primary-dark)); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">🔒</span>
                <div>
                    <div style="font-size: 0.9rem; color: #64748b;">Encryption</div>
                    <div style="font-size: 1.2rem; font-weight: 500; color: #1e293b;">AES-256 (Military Grade)</div>
                </div>
            </div>
            <div style="display: flex; align-items: center; gap: 15px; margin-bottom: 1.5rem;">
                <span style="font-size: 2rem; background: linear-gradient(to right, var(--primary), var(--primary-dark)); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">🛡️</span>
                <div>
                    <div style="font-size: 0.9rem; color: #64748b;">Password Hashing</div>
                    <div style="font-size: 1.2rem; font-weight: 500; color: #1e293b;">PBKDF2 with SHA-256</div>
                </div>
            </div>
            <div style="display: flex; align-items: center; gap: 15px;">
                <span style="font-size: 2rem; background: linear-gradient(to right, var(--primary), var(--primary-dark)); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">🔐</span>
                <div>
                    <div style="font-size: 0.9rem; color: #64748b;">Data Protection</div>
                    <div style="font-size: 1.2rem; font-weight: 500; color: #1e293b;">End-to-End Encryption</div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()