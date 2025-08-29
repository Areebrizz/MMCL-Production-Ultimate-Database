import streamlit as st
import pandas as pd
from supabase import create_client
from datetime import datetime, timedelta
import time
import jwt
import hashlib
import secrets

# Force clear cache and show version
APP_VERSION = "1.0"
st.set_page_config(
    page_title="MMCL Production Platform",
    page_icon="🏭",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Show version for debugging
st.sidebar.write(f"🚀 App Version: {APP_VERSION}")
st.sidebar.write(f"📅 Loaded: {datetime.now().strftime('%H:%M:%S')}")

# Configuration
class AppConfig:
    def __init__(self):
        self.SECRET_KEY = st.secrets.get("SECRET_KEY", "dev-secret-key-2024")
        self.SUPABASE_URL = st.secrets.get("SUPABASE_URL")
        self.SUPABASE_KEY = st.secrets.get("SUPABASE_KEY")

config = AppConfig()

# Database connection
def init_connection():
    if not config.SUPABASE_URL or not config.SUPABASE_KEY:
        st.error("Missing Supabase credentials")
        return None
    try:
        return create_client(config.SUPABASE_URL, config.SUPABASE_KEY)
    except Exception as e:
        st.error(f"Connection failed: {e}")
        return None

supabase = init_connection()

# Password utilities
def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    return f"{salt}${hashlib.sha256((password + salt).encode()).hexdigest()}"

def verify_password(plain: str, hashed: str) -> bool:
    try:
        salt, stored_hash = hashed.split('$')
        return hashlib.sha256((plain + salt).encode()).hexdigest() == stored_hash
    except:
        return False

def check_password_strength(password: str) -> bool:
    return (len(password) >= 8 and 
            any(c.isupper() for c in password) and 
            any(c.isdigit() for c in password))

# Database operations
def get_user(username: str):
    if not supabase: return None
    try:
        response = supabase.table("users").select("*").eq("username", username).execute()
        return response.data[0] if response.data else None
    except:
        return None

def create_user(username, password, role="viewer", approved=False, department=None, email=None):
    if not supabase: return None
    try:
        user_data = {
            "username": username,
            "password": hash_password(password),
            "role": role,
            "approved": approved,
            "department": department,
            "email": email,
            "created_at": datetime.utcnow().isoformat()
        }
        response = supabase.table("users").insert(user_data).execute()
        return response.data[0] if response.data else None
    except:
        return None

def save_production_data(data):
    if not supabase: return False
    try:
        response = supabase.table("production_metrics").insert(data).execute()
        return bool(response.data)
    except:
        return False

def get_production_data(department=None, days=7):
    if not supabase: return pd.DataFrame()
    try:
        query = supabase.table("production_metrics").select("*")
        if department and department != "All":
            query = query.eq("department", department)
        response = query.execute()
        return pd.DataFrame(response.data) if response.data else pd.DataFrame()
    except:
        return pd.DataFrame()

# Session state
if "auth" not in st.session_state:
    st.session_state.update({
        "authenticated": False,
        "username": None,
        "role": None,
        "user_id": None,
        "department": None
    })

# Setup admin user
def setup_admin():
    if not get_user("admin"):
        create_user("admin", "Admin123!", "admin", True, "System", "admin@mmcl.com")

# Authentication pages
def login_page():
    st.title("🔐 MMCL Production Login")
    
    with st.form("login"):
        user = st.text_input("Username")
        pwd = st.text_input("Password", type="password")
        
        if st.form_submit_button("Login"):
            user_data = get_user(user)
            if user_data and verify_password(pwd, user_data["password"]) and user_data["approved"]:
                st.session_state.update({
                    "authenticated": True,
                    "username": user_data["username"],
                    "role": user_data["role"],
                    "user_id": user_data["id"],
                    "department": user_data.get("department")
                })
                st.success("Login successful!")
                time.sleep(1)
                st.rerun()
            else:
                st.error("Invalid credentials or account not approved")

def register_page():
    st.title("📝 Create Account")
    
    with st.form("register"):
        user = st.text_input("Username (3-20 chars)")
        pwd = st.text_input("Password", type="password")
        confirm = st.text_input("Confirm Password", type="password")
        dept = st.selectbox("Department", ["Assembly Shop", "Paint Shop", "Weld Shop", "QAHSE", "PDI"])
        email = st.text_input("Email")
        
        if st.form_submit_button("Register"):
            if not user or len(user) < 3:
                st.error("Username too short")
            elif pwd != confirm:
                st.error("Passwords don't match")
            elif not check_password_strength(pwd):
                st.error("Password needs 8+ chars, uppercase, and number")
            elif get_user(user):
                st.error("Username exists")
            else:
                if create_user(user, pwd, "viewer", False, dept, email):
                    st.success("Account created! Awaiting approval.")
                else:
                    st.error("Registration failed")

# Main app pages
def production_page():
    st.title("🏭 Production Entry")
    
    with st.form("production"):
        date = st.date_input("Date", datetime.now())
        shift = st.selectbox("Shift", ["Morning", "Evening", "Night"])
        planned = st.number_input("Planned Units", min_value=0, value=100)
        actual = st.number_input("Actual Units", min_value=0, value=95)
        scrap = st.number_input("Scrap Units", min_value=0, value=3)
        notes = st.text_area("Notes")
        
        if st.form_submit_button("💾 Save"):
            data = {
                "date": date.isoformat(),
                "shift": shift,
                "production_plan": planned,
                "production_actual": actual,
                "scrap": scrap,
                "notes": notes,
                "entered_by": st.session_state.username,
                "department": st.session_state.department,
                "availability": 95.0,
                "performance": (actual/planned*100 if planned > 0 else 0),
                "quality": ((actual-scrap)/actual*100 if actual > 0 else 0),
                "oee_score": 90.0
            }
            
            if save_production_data(data):
                st.success("Data saved!")
            else:
                st.error("Save failed")

def dashboard_page():
    st.title("📊 Production Dashboard")
    
    dept = st.selectbox("Filter Department", ["All", "Assembly Shop", "Paint Shop", "Weld Shop"])
    data = get_production_data(dept if dept != "All" else None)
    
    if not data.empty:
        st.metric("Total Records", len(data))
        st.metric("Average OEE", f"{data['oee_score'].mean():.1f}%")
        
        st.dataframe(data[['date', 'shift', 'production_actual', 'oee_score']].tail(10))
    else:
        st.info("No production data found")

# Main app
def main():
    setup_admin()
    
    if not st.session_state.authenticated:
        tab1, tab2 = st.tabs(["Login", "Register"])
        with tab1: login_page()
        with tab2: register_page()
    else:
        st.sidebar.title(f"Welcome, {st.session_state.username}")
        st.sidebar.write(f"Role: {st.session_state.role}")
        st.sidebar.write(f"Department: {st.session_state.department}")
        
        pages = ["Dashboard", "Production Entry"]
        if st.session_state.role == "admin":
            pages.append("Admin")
        
        page = st.sidebar.selectbox("Navigation", pages)
        
        if st.sidebar.button("Logout"):
            st.session_state.clear()
            st.rerun()
        
        if page == "Dashboard": dashboard_page()
        elif page == "Production Entry": production_page()
        elif page == "Admin": st.title("Admin Panel - Coming Soon")

if __name__ == "__main__":
    main()
