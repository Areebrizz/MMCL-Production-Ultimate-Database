import streamlit as st
import pandas as pd
from supabase import create_client
from datetime import datetime, timedelta
import time
import jwt
import warnings
import pytz
import hashlib
import secrets
from functools import wraps

warnings.filterwarnings('ignore')

# -------------------------
# Page Config
# -------------------------
st.set_page_config(
    page_title="MMCL Production Intelligence Platform",
    page_icon="🏭",
    layout="wide",
    initial_sidebar_state="expanded"
)

# -------------------------
# Enhanced Configuration
# -------------------------
class EnhancedConfig:
    def __init__(self):
        secrets_dict = st.secrets if hasattr(st, "secrets") else {}
        self.SECRET_KEY = secrets_dict.get("SECRET_KEY", "mmcl-production-secret-key-2024")
        self.PASSWORD_EXPIRY_DAYS = 90
        self.SESSION_TIMEOUT_MINUTES = 60
        self.SUPABASE_URL = secrets_dict.get("SUPABASE_URL")
        self.SUPABASE_KEY = secrets_dict.get("SUPABASE_KEY")
        
config = EnhancedConfig()

# -------------------------
# Supabase Connection
# -------------------------
@st.cache_resource
def init_connection():
    if not config.SUPABASE_URL or not config.SUPABASE_KEY:
        st.error("Supabase credentials not found. Please check your secrets.toml")
        return None
    try:
        client = create_client(config.SUPABASE_URL, config.SUPABASE_KEY)
        # Simple connection test
        client.table("users").select("count", count="exact").limit(1).execute()
        return client
    except Exception as e:
        st.error(f"Database connection failed: {e}")
        return None

supabase = init_connection()

# -------------------------
# Error Handling
# -------------------------
def handle_database_errors(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            st.error(f"Database operation failed: {str(e)}")
            return None
    return wrapper

# -------------------------
# Password Utilities
# -------------------------
def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    hash_obj = hashlib.sha256((password + salt).encode())
    return f"{salt}${hash_obj.hexdigest()}"

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        if not hashed_password or '$' not in hashed_password:
            return False
        salt, stored_hash = hashed_password.split('$')
        hash_obj = hashlib.sha256((plain_password + salt).encode())
        return hash_obj.hexdigest() == stored_hash
    except:
        return False

def check_password_strength(password: str) -> int:
    strength = 0
    if len(password) >= 8:  # Reduced from 12 for better UX
        strength += 1
    if any(c.isupper() for c in password) and any(c.islower() for c in password):
        strength += 1
    if any(c.isdigit() for c in password):
        strength += 1
    return strength

def validate_username(username: str) -> bool:
    return 3 <= len(username) <= 20 and username.isalnum()

def is_password_expired(password_changed_date: str) -> bool:
    if not password_changed_date:
        return True
    try:
        change_date = datetime.fromisoformat(password_changed_date.replace('Z', '+00:00'))
        expiry_date = change_date + timedelta(days=config.PASSWORD_EXPIRY_DAYS)
        return datetime.utcnow() > expiry_date
    except:
        return True

# -------------------------
# JWT Token
# -------------------------
def generate_jwt_token(user_data: dict) -> str:
    payload = {
        "user_id": user_data["id"],
        "username": user_data["username"],
        "role": user_data["role"],
        "department": user_data.get("department"),
        "exp": datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, config.SECRET_KEY, algorithm="HS256")

# -------------------------
# Session State
# -------------------------
if "authenticated" not in st.session_state:
    st.session_state.update({
        "authenticated": False,
        "username": None,
        "role": None,
        "user_id": None,
        "department": None,
        "last_activity": datetime.now().isoformat(),
        "password_change_required": False
    })

# -------------------------
# Database Operations
# -------------------------
@handle_database_errors
def get_user(username: str) -> dict:
    if not supabase:
        return None
    response = supabase.table("users").select("*").eq("username", username).execute()
    return response.data[0] if response.data else None

@handle_database_errors
def create_user(username: str, password: str, role: str = "viewer", approved: bool = False, department: str = None, email: str = None) -> dict:
    if not supabase:
        return None
    hashed_password = hash_password(password)
    user_data = {
        "username": username,
        "password": hashed_password,
        "role": role,
        "approved": approved,
        "department": department,
        "email": email,
        "created_at": datetime.utcnow().isoformat(),
        "password_changed_at": datetime.utcnow().isoformat()
    }
    response = supabase.table("users").insert(user_data).execute()
    return response.data[0] if response.data else None

@handle_database_errors
def update_password(user_id: str, new_password: str) -> bool:
    if not supabase:
        return False
    hashed_password = hash_password(new_password)
    response = supabase.table("users").update({
        "password": hashed_password,
        "password_changed_at": datetime.utcnow().isoformat()
    }).eq("id", user_id).execute()
    return bool(response.data)

@handle_database_errors
def save_production_data(data: dict) -> bool:
    if not supabase:
        return False
    response = supabase.table("production_metrics").insert(data).execute()
    return bool(response.data)

@handle_database_errors
def get_production_data(department: str = None, start_date: str = None, end_date: str = None):
    if not supabase:
        return pd.DataFrame()
    
    query = supabase.table("production_metrics").select("*")
    
    if department and department != "All":
        query = query.eq("department", department)
    if start_date:
        query = query.gte("date", start_date)
    if end_date:
        query = query.lte("date", end_date)
    
    response = query.execute()
    return pd.DataFrame(response.data) if response.data else pd.DataFrame()

# -------------------------
# Admin Setup
# -------------------------
GOD_ADMIN_USERNAME = "admin"
GOD_ADMIN_PASSWORD = "Admin@12345!"

def setup_god_admin():
    admin_user = get_user(GOD_ADMIN_USERNAME)
    if not admin_user:
        result = create_user(GOD_ADMIN_USERNAME, GOD_ADMIN_PASSWORD, "admin", True, "System", "admin@mmcl.com")
        if result:
            st.sidebar.success("Admin account created")

# -------------------------
# Authentication Pages
# -------------------------
def auth_page():
    tab1, tab2 = st.tabs(["🔐 Login", "📝 Register"])
    
    with tab1:
        st.header("Login")
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Login")
            
            if submitted:
                user = get_user(username)
                if not user:
                    st.error("User not found")
                    return
                if not verify_password(password, user["password"]):
                    st.error("Invalid password")
                    return
                if not user["approved"]:
                    st.error("Account pending approval")
                    return
                
                st.session_state.update({
                    "authenticated": True,
                    "username": user["username"],
                    "role": user["role"],
                    "user_id": user["id"],
                    "department": user.get("department"),
                    "password_change_required": is_password_expired(user.get("password_changed_at"))
                })
                st.success("Login successful!")
                time.sleep(1)
                st.rerun()
    
    with tab2:
        st.header("Register")
        with st.form("register_form"):
            new_username = st.text_input("Username")
            new_password = st.text_input("Password", type="password")
            confirm_password = st.text_input("Confirm Password", type="password")
            department = st.selectbox("Department", ["Assembly Shop", "Paint Shop", "Weld Shop", "QAHSE", "PDI"])
            email = st.text_input("Email")
            
            submitted = st.form_submit_button("Create Account")
            
            if submitted:
                if not validate_username(new_username):
                    st.error("Invalid username format")
                elif new_password != confirm_password:
                    st.error("Passwords don't match")
                elif check_password_strength(new_password) < 2:
                    st.error("Password too weak")
                elif get_user(new_username):
                    st.error("Username exists")
                else:
                    user = create_user(new_username, new_password, "viewer", False, department, email)
                    if user:
                        st.success("Account created! Waiting for approval.")
                    else:
                        st.error("Creation failed")

# -------------------------
# Production Entry Page
# -------------------------
def production_entry_page():
    st.header(f"Production Entry - {st.session_state.department}")
    
    with st.form("production_form"):
        col1, col2 = st.columns(2)
        
        with col1:
            date = st.date_input("Date", datetime.now())
            shift = st.selectbox("Shift", ["Morning", "Evening", "Night"])
            manpower = st.number_input("Manpower", min_value=0, value=10)
        
        with col2:
            planned = st.number_input("Planned Production", min_value=0, value=100)
            actual = st.number_input("Actual Production", min_value=0, value=95)
            scrap = st.number_input("Scrap Quantity", min_value=0, value=2)
        
        downtime = st.number_input("Downtime Hours", min_value=0.0, value=0.5, step=0.1)
        notes = st.text_area("Notes")
        
        submitted = st.form_submit_button("Save Record")
        
        if submitted:
            data = {
                "date": date.isoformat(),
                "shift": shift,
                "manpower_available": manpower,
                "production_plan": planned,
                "production_actual": actual,
                "scrap": scrap,
                "downtime_hours": downtime,
                "notes": notes,
                "entered_by": st.session_state.username,
                "department": st.session_state.department,
                "availability": 95.0,
                "performance": 98.0,
                "quality": 97.0,
                "oee_score": 90.0
            }
            
            if save_production_data(data):
                st.success("Production data saved!")
            else:
                st.error("Failed to save data")

# -------------------------
# Dashboard Page
# -------------------------
def dashboard_page():
    st.header("Production Dashboard")
    
    col1, col2 = st.columns(2)
    with col1:
        start_date = st.date_input("Start Date", datetime.now() - timedelta(days=7))
    with col2:
        end_date = st.date_input("End Date", datetime.now())
    
    department = st.selectbox("Department", ["All", "Assembly Shop", "Paint Shop", "Weld Shop", "QAHSE", "PDI"])
    
    data = get_production_data(
        department if department != "All" else None,
        start_date.isoformat(),
        end_date.isoformat()
    )
    
    if not data.empty:
        st.metric("Total Records", len(data))
        st.metric("Average OEE", f"{data['oee_score'].mean():.1f}%")
        
        st.subheader("Recent Production")
        st.dataframe(data[['date', 'shift', 'production_actual', 'oee_score']].tail(10))
    else:
        st.info("No production data found")

# -------------------------
# Profile Page
# -------------------------
def profile_page():
    st.header("User Profile")
    
    user = get_user(st.session_state.username)
    if not user:
        st.error("User not found")
        return
    
    st.info(f"**Username:** {user['username']}")
    st.info(f"**Role:** {user['role']}")
    st.info(f"**Department:** {user.get('department', 'None')}")
    st.info(f"**Status:** {'Approved' if user['approved'] else 'Pending'}")
    
    if st.session_state.password_change_required:
        st.warning("Your password needs to be changed")
        
        with st.form("change_password"):
            current = st.text_input("Current Password", type="password")
            new = st.text_input("New Password", type="password")
            confirm = st.text_input("Confirm Password", type="password")
            
            if st.form_submit_button("Change Password"):
                if not verify_password(current, user["password"]):
                    st.error("Current password incorrect")
                elif new != confirm:
                    st.error("New passwords don't match")
                elif check_password_strength(new) < 2:
                    st.error("Password too weak")
                elif update_password(st.session_state.user_id, new):
                    st.session_state.password_change_required = False
                    st.success("Password updated!")
                    st.rerun()
                else:
                    st.error("Password update failed")

# -------------------------
# Navigation & Main App
# -------------------------
def main_app():
    st.sidebar.title("🏭 MMCL Production")
    st.sidebar.write(f"Welcome, **{st.session_state.username}**")
    st.sidebar.write(f"*{st.session_state.role} - {st.session_state.department}*")
    st.sidebar.divider()
    
    pages = ["📊 Dashboard", "🏭 Production Entry", "👤 Profile"]
    if st.session_state.role == "admin":
        pages.append("⚙️ Admin")
    
    page = st.sidebar.radio("Navigation", pages)
    
    if st.sidebar.button("🚪 Logout"):
        st.session_state.clear()
        st.rerun()
    
    # Page routing
    if page == "📊 Dashboard":
        dashboard_page()
    elif page == "🏭 Production Entry":
        production_entry_page()
    elif page == "👤 Profile":
        profile_page()
    elif page == "⚙️ Admin":
        st.header("Admin Panel")
        st.info("Admin features coming soon")

def check_session_timeout():
    try:
        last_activity = datetime.fromisoformat(st.session_state.last_activity)
        return (datetime.now() - last_activity).total_seconds() > config.SESSION_TIMEOUT_MINUTES * 60
    except:
        return False

def main():
    setup_god_admin()
    
    if not st.session_state.authenticated:
        auth_page()
    else:
        if check_session_timeout():
            st.warning("Session expired")
            st.session_state.clear()
            st.rerun()
        else:
            st.session_state.last_activity = datetime.now().isoformat()
            main_app()

if __name__ == "__main__":
    main()
