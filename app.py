import streamlit as st
import pandas as pd
from supabase import create_client, Client
from datetime import datetime, date, timedelta
import time
import bcrypt

# -------------------------
# Page Config
# -------------------------
st.set_page_config(
    page_title="MMCL Production Ultimate Database",
    page_icon="🏭",
    layout="wide",
    initial_sidebar_state="expanded"
)

# -------------------------
# Connect to Supabase
# -------------------------
@st.cache_resource
def init_connection():
    SUPABASE_URL = st.secrets["SUPABASE_URL"]
    SUPABASE_KEY = st.secrets["SUPABASE_KEY"]
    return create_client(SUPABASE_URL, SUPABASE_KEY)

supabase = init_connection()

# -------------------------
# Authentication & Session State
# -------------------------
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
    st.session_state.username = None
    st.session_state.role = None
    st.session_state.user_id = None
    st.session_state.department = None
    st.session_state.last_activity = datetime.now().isoformat()
    st.session_state.last_activity_update = time.time()

# -------------------------
# Security Functions
# -------------------------
def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def check_password(password: str, hashed: str) -> bool:
    """Check password against hash"""
    return bcrypt.checkpw(password.encode(), hashed.encode())

def auto_logout_check():
    """Auto logout after inactivity"""
    MAX_IDLE_MINUTES = 30
    if "last_activity" in st.session_state:
        idle_time = datetime.utcnow() - datetime.fromisoformat(st.session_state.last_activity)
        if idle_time > timedelta(minutes=MAX_IDLE_MINUTES):
            if "user_id" in st.session_state:
                set_user_online_status(st.session_state.user_id, False)
                log_audit_event(st.session_state.user_id, "auto_logout", "system", "N/A", "Auto logout due to inactivity")
            st.warning("You were logged out due to inactivity.")
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()

def update_activity():
    """Update user activity timestamp"""
    st.session_state.last_activity = datetime.utcnow().isoformat()
    if "user_id" in st.session_state:
        set_user_online_status(st.session_state.user_id, True)

# -------------------------
# Database Functions
# -------------------------
def get_user(username):
    try:
        response = supabase.table("users").select("*").eq("username", username).execute()
        return response.data[0] if response.data else None
    except Exception as e:
        st.error(f"Error fetching user: {str(e)}")
        return None

def get_all_users():
    try:
        response = supabase.table("users").select("*").execute()
        # Ensure each user has all required fields with defaults
        for user in response.data:
            user.setdefault('approved', False)
            user.setdefault('role', 'viewer')
            user.setdefault('department', 'Not set')
            user.setdefault('is_online', False)
        return response.data
    except Exception as e:
        st.error(f"Error fetching users: {str(e)}")
        return []

def get_online_users():
    try:
        response = supabase.table("users").select("username, role, department, last_activity").eq("is_online", True).execute()
        return response.data
    except Exception as e:
        st.error(f"Error fetching online users: {str(e)}")
        return []

def create_user(username, password, role="viewer", approved=False, department=None):
    try:
        hashed_password = hash_password(password)
        user_data = {
            "username": username,
            "password_hash": hashed_password,
            "role": role,
            "approved": approved,
            "department": department,
            "created_at": datetime.utcnow().isoformat(),
            "is_online": False
        }
        response = supabase.table("users").insert(user_data).execute()
        return response.data[0] if response.data else None
    except Exception as e:
        st.error(f"Error creating user: {str(e)}")
        return None

def update_user_role(user_id, new_role):
    try:
        response = supabase.table("users").update({"role": new_role}).eq("id", user_id).execute()
        return True
    except Exception as e:
        st.error(f"Error updating user role: {str(e)}")
        return False

def approve_user(user_id):
    try:
        response = supabase.table("users").update({"approved": True}).eq("id", user_id).execute()
        return True
    except Exception as e:
        st.error(f"Error approving user: {str(e)}")
        return False

def reset_user_password(user_id, new_password):
    try:
        hashed_password = hash_password(new_password)
        response = supabase.table("users").update({"password_hash": hashed_password}).eq("id", user_id).execute()
        return True
    except Exception as e:
        st.error(f"Error resetting password: {str(e)}")
        return False

def update_user_department(user_id, department):
    try:
        response = supabase.table("users").update({"department": department}).eq("id", user_id).execute()
        return True
    except Exception as e:
        st.error(f"Error updating department: {str(e)}")
        return False

def set_user_online_status(user_id, is_online):
    try:
        response = supabase.table("users").update({
            "is_online": is_online,
            "last_activity": datetime.utcnow().isoformat()
        }).eq("id", user_id).execute()
        return True
    except Exception as e:
        st.error(f"Error setting online status: {str(e)}")
        return False

def create_access_request(username, requested_role, reason):
    try:
        request_data = {
            "username": username,
            "requested_role": requested_role,
            "reason": reason,
            "status": "pending",
            "requested_at": datetime.utcnow().isoformat(),
            "request_type": "role_access"
        }
        response = supabase.table("access_requests").insert(request_data).execute()
        return response.data[0] if response.data else None
    except Exception as e:
        st.error(f"Error creating access request: {str(e)}")
        return None

def create_password_change_request(username, new_password):
    try:
        hashed_password = hash_password(new_password)
        request_data = {
            "username": username,
            "new_password_hash": hashed_password,
            "requested_role": "none",
            "status": "pending",
            "requested_at": datetime.utcnow().isoformat(),
            "request_type": "password_change"
        }
        response = supabase.table("access_requests").insert(request_data).execute()
        return response.data is not None
    except Exception as e:
        st.error(f"Error creating password change request: {str(e)}")
        return False

def get_pending_requests():
    try:
        response = supabase.table("access_requests").select("*").eq("status", "pending").eq("request_type", "role_access").execute()
        return response.data
    except Exception as e:
        st.error(f"Error fetching pending requests: {str(e)}")
        return []

def get_password_change_requests():
    try:
        response = supabase.table("access_requests").select("*").eq("status", "pending").eq("request_type", "password_change").execute()
        return response.data
    except Exception as e:
        st.error(f"Error fetching password change requests: {str(e)}")
        return []

def update_request_status(request_id, status, approved_by):
    try:
        response = supabase.table("access_requests").update({
            "status": status,
            "approved_by": approved_by,
            "reviewed_at": datetime.utcnow().isoformat()
        }).eq("id", request_id).execute()
        return True
    except Exception as e:
        st.error(f"Error updating request status: {str(e)}")
        return False

def approve_password_change(request_id, approved_by):
    try:
        response = supabase.table("access_requests").select("*").eq("id", request_id).execute()
        if not response.data:
            st.error("Password change request not found!")
            return False
        
        request = response.data[0]
        user = get_user(request['username'])
        
        if not user:
            st.error(f"User {request['username']} not found!")
            return False
        
        update_response = supabase.table("users").update({
            "password_hash": request['new_password_hash']
        }).eq("id", user['id']).execute()
        
        if update_response.data:
            log_audit_event(st.session_state.user_id, "password_changed", "user", user['id'], f"Admin changed password for {user['username']}")
            return True
        else:
            st.error("Failed to update user password!")
            return False
        
    except Exception as e:
        st.error(f"Error approving password change: {str(e)}")
        return False

def log_audit_event(user_id, action, target_type, target_id, details):
    try:
        audit_data = {
            "user_id": user_id,
            "username": st.session_state.username,
            "action": action,
            "target_type": target_type,
            "target_id": target_id,
            "details": details,
            "timestamp": datetime.utcnow().isoformat(),
            "ip_address": "N/A"
        }
        response = supabase.table("audit_log").insert(audit_data).execute()
        return True
    except Exception as e:
        st.error(f"Error logging audit event: {str(e)}")
        return False

def get_audit_logs(limit=100):
    try:
        response = supabase.table("audit_log").select("*").order("timestamp", desc=True).limit(limit).execute()
        return response.data
    except Exception as e:
        st.error(f"Error fetching audit logs: {str(e)}")
        return []

def can_edit_record(record_date):
    """Check if record can be edited (within 7 days)"""
    try:
        record_date = pd.to_datetime(record_date).date()
        today = date.today()
        return (today - record_date).days <= 7
    except:
        return False

def update_password_request_status(request_id, status, approved_by):
    try:
        response = supabase.table("access_requests").update({
            "status": status,
            "approved_by": approved_by,
            "reviewed_at": datetime.utcnow().isoformat()
        }).eq("id", request_id).execute()
        return True
    except Exception as e:
        st.error(f"Error updating password request status: {str(e)}")
        return False

def get_production_metrics(start_date=None, end_date=None, department=None):
    try:
        query = supabase.table("production_metrics").select("*")
        if start_date:
            query = query.gte("date", str(start_date))
        if end_date:
            query = query.lte("date", str(end_date))
        if department and department != "All":
            query = query.eq("department", department)
        response = query.execute()
        return response.data
    except Exception as e:
        st.error(f"Error fetching production metrics: {str(e)}")
        return []

def get_quality_metrics(start_date=None, end_date=None, department=None):
    try:
        query = supabase.table("quality_metrics").select("*")
        if start_date:
            query = query.gte("date", str(start_date))
        if end_date:
            query = query.lte("date", str(end_date))
        if department and department != "All":
            query = query.eq("department", department)
        response = query.execute()
        return response.data
    except Exception as e:
        st.error(f"Error fetching quality metrics: {str(e)}")
        return []

def get_recent_production_records(limit=50):
    try:
        response = supabase.table("production_metrics").select("*").order("date", desc=True).limit(limit).execute()
        return response.data
    except Exception as e:
        st.error(f"Error fetching recent production records: {str(e)}")
        return []

def get_record_counts():
    try:
        production_response = supabase.table("production_metrics").select("id", count="exact").execute()
        quality_response = supabase.table("quality_metrics").select("id", count="exact").execute()
        return {
            "production": production_response.count if hasattr(production_response, 'count') else 0,
            "quality": quality_response.count if hasattr(quality_response, 'count') else 0
        }
    except Exception as e:
        st.error(f"Error fetching record counts: {str(e)}")
        return {"production": 0, "quality": 0}
        
def get_pending_users():
    """Get all users waiting for approval"""
    try:
        response = supabase.table("users").select("*").eq("approved", False).execute()
        return response.data
    except Exception as e:
        st.error(f"Error fetching pending users: {str(e)}")
        return []

# -------------------------
# Pre-defined God Admin
# -------------------------
GOD_ADMIN_USERNAME = "admin"
GOD_ADMIN_PASSWORD = st.secrets.get("GOD_ADMIN_PASSWORD", "admin123")

def setup_god_admin():
    """Create/update god admin account securely"""
    try:
        existing_admin = get_user(GOD_ADMIN_USERNAME)
        hashed_password = hash_password(GOD_ADMIN_PASSWORD)
        
        if not existing_admin:
            user_data = {
                "username": GOD_ADMIN_USERNAME,
                "password_hash": hashed_password,
                "role": "admin",
                "approved": True,
                "department": "System",
                "created_at": datetime.utcnow().isoformat(),
                "is_online": False
            }
            response = supabase.table("users").insert(user_data).execute()
            if response.data:
                st.success("God Admin account created!")
            else:
                st.warning("God Admin account might already exist.")
        else:
            # Sync password if changed in secrets
            if not check_password(GOD_ADMIN_PASSWORD, existing_admin["password_hash"]):
                response = supabase.table("users").update({
                    "password_hash": hashed_password
                }).eq("username", GOD_ADMIN_USERNAME).execute()
                if response.data:
                    st.warning("God Admin password updated!")
    except Exception as e:
        st.error(f"Error setting up God Admin: {str(e)}")

# -------------------------
# Login/Registration Page
# -------------------------
def auth_page():
    tab1, tab2 = st.tabs(["🔐 Login", "📝 Register"])
    
    with tab1:
        st.header("Login to MMCL-Production Ultimate Database")
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Login")
            
            if submitted:
                user = get_user(username)
                if user and check_password(password, user["password_hash"]) and user["approved"]:
                    st.session_state.authenticated = True
                    st.session_state.username = user["username"]
                    st.session_state.role = user["role"]
                    st.session_state.user_id = user["id"]
                    st.session_state.department = user.get("department")
                    st.session_state.last_activity = datetime.utcnow().isoformat()
                    set_user_online_status(user["id"], True)
                    log_audit_event(user["id"], "login", "system", "N/A", "User logged in")
                    st.success("Login successful!")
                    time.sleep(0.5)
                    st.rerun()
                else:
                    if user and not user["approved"]:
                        st.error("Account not yet approved. Please wait for admin approval.")
                    else:
                        st.error("Invalid credentials or account not approved")
    
    with tab2:
        st.header("Create New Account")
        with st.form("register_form"):
            new_username = st.text_input("Choose Username")
            new_password = st.text_input("Choose Password", type="password")
            confirm_password = st.text_input("Confirm Password", type="password")
            department = st.selectbox("Department", ["Assembly Shop", "Paint Shop", "Weld Shop", "QAHSE", "PDI"])
            
            submitted_reg = st.form_submit_button("Create Account")
            
            if submitted_reg:
                if new_password != confirm_password:
                    st.error("Passwords do not match!")
                elif len(new_password) < 8:
                    st.error("Password must be at least 8 characters long!")
                elif get_user(new_username):
                    st.error("Username already exists!")
                else:
                    user = create_user(new_username, new_password, "viewer", False, department)
                    if user:
                        st.success("Account created! Please wait for admin approval.")
                        st.info("You will be able to login once an admin approves your account.")
                    else:
                        st.error("Failed to create account")

# -------------------------
# Navigation Sidebar
# -------------------------
def show_sidebar():
    with st.sidebar:
        st.title(f"MMCL Production Ultimate Database")
        st.markdown(f"**Welcome, {st.session_state.username}**")
        st.markdown(f"*Role: {st.session_state.role}*")
        if st.session_state.department:
            st.markdown(f"*Department: {st.session_state.department}*")
        st.markdown("---")
        
        # Update activity on navigation
        update_activity()
        
        # Navigation options based on role and department
        pages = ["Dashboard", "Profile"]
        
        # Production departments get their specific production entry
        if st.session_state.role in ["supervisor", "admin"] and st.session_state.department in ["Assembly Shop", "Paint Shop", "Weld Shop", "PDI"]:
            pages.append("Production Entry")
        
        # QAHSE gets their quality entry
        if st.session_state.role in ["supervisor", "admin"] and st.session_state.department == "QAHSE":
            pages.append("Quality Data Entry")
        
        if st.session_state.role != "admin":
            pages.append("Request Access")
        
        if st.session_state.role == "admin":
            pages.extend(["User Management", "Access Requests", "Production Control", "Audit Log", "System Monitor"])
        
        selected_page = st.radio("Navigation", pages)
        
        st.markdown("---")
        
        # Online users count
        online_users = get_online_users()
        st.markdown(f"**Online Users: {len(online_users)}**")
        
        # Auto logout warning
        if "last_activity" in st.session_state:
            idle_time = datetime.utcnow() - datetime.fromisoformat(st.session_state.last_activity)
            max_idle = timedelta(minutes=30)
            remaining = max_idle - idle_time
            if remaining < timedelta(minutes=5):
                st.warning(f"Auto logout in {int(remaining.total_seconds() / 60)} minutes")
        
        if st.button("🚪 Logout"):
            if "user_id" in st.session_state:
                set_user_online_status(st.session_state.user_id, False)
                log_audit_event(st.session_state.user_id, "logout", "system", "N/A", "User logged out")
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()
    
    return selected_page

# -------------------------
# Profile Page
# -------------------------
def profile_page():
    update_activity()
    st.header("👤 User Profile")
    
    # Get current user data
    user = get_user(st.session_state.username)
    
    if user:
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Profile Information")
            st.write(f"**Username:** {user['username']}")
            st.write(f"**Role:** {user['role']}")
            st.write(f"**Department:** {user.get('department', 'Not assigned')}")
            st.write(f"**Account Status:** {'✅ Approved' if user['approved'] else '⏳ Pending approval'}")
            st.write(f"**Member since:** {pd.to_datetime(user['created_at']).strftime('%Y-%m-%d') if user.get('created_at') else 'N/A'}")
        
        with col2:
            st.subheader("Change Password")
            with st.form("change_password_form"):
                current_password = st.text_input("Current Password", type="password")
                new_password = st.text_input("New Password", type="password")
                confirm_password = st.text_input("Confirm New Password", type="password")
                
                submitted = st.form_submit_button("Request Password Change")
                
                if submitted:
                    # Reset error state
                    error_message = None
                    
                    # Validate current password
                    if not check_password(current_password, user['password_hash']):
                        error_message = "Current password is incorrect!"
                    
                    # Validate new password
                    elif not new_password:
                        error_message = "New password cannot be empty!"
                    elif len(new_password) < 8:
                        error_message = "Password must be at least 8 characters long!"
                    
                    # Validate password confirmation
                    elif new_password != confirm_password:
                        error_message = "New passwords do not match!"
                    
                    # If validation passed, create the request
                    if error_message:
                        st.error(error_message)
                    else:
                        # Create password change request
                        success = create_password_change_request(st.session_state.username, new_password)
                        if success:
                            st.success("✅ Password change request submitted! Waiting for admin approval.")
                            log_audit_event(st.session_state.user_id, "password_change_request", "user", user['id'], "Requested password change")
                        else:
                            st.error("❌ Failed to submit password change request. Please try again.")
    
    else:
        st.error("User not found!")

# -------------------------
# Dashboard Page (Enhanced with OEE Analytics)
# -------------------------
def dashboard_page():
    update_activity()
    st.header("📊 Production Dashboard")
    
    # Date range filter with month selection option
    col1, col2, col3 = st.columns([1, 1, 2])
    
    with col1:
        date_range = st.selectbox("View by", 
                                ["Today", "This Week", "This Month", "Custom Range"])
    
    with col2:
        if date_range == "Custom Range":
            start_date = st.date_input("Start Date", value=date.today().replace(day=1))
            end_date = st.date_input("End Date", value=date.today())
        else:
            today = date.today()
            if date_range == "Today":
                start_date = today
                end_date = today
            elif date_range == "This Week":
                start_date = today - timedelta(days=today.weekday())
                end_date = start_date + timedelta(days=6)
            else:  # This Month
                start_date = today.replace(day=1)
                end_date = (start_date + timedelta(days=32)).replace(day=1) - timedelta(days=1)
    
    # Department filter
    departments = ["All"] + list(pd.DataFrame(get_all_users())["department"].dropna().unique())
    with col3:
        department_filter = st.selectbox("Filter by Department", departments)
    
    # Fetch production data
    records = get_production_metrics(start_date, end_date, department_filter)
    
    if records:
        df = pd.DataFrame(records)
        df["date"] = pd.to_datetime(df["date"], errors="coerce")
        
        # Calculate overall OEE for the period
        overall_oee = calculate_daily_oee(records)
        
        # KPI Metrics
        st.subheader("📈 Overall Equipment Effectiveness (OEE)")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Availability", f"{overall_oee['availability']}%")
        with col2:
            st.metric("Performance", f"{overall_oee['performance']}%")
        with col3:
            st.metric("Quality", f"{overall_oee['quality']}%")
        with col4:
            st.metric("Overall OEE", f"{overall_oee['oee']}%", 
                     delta_color="normal" if overall_oee['oee'] >= 85 else "inverse")
        
        # World-class OEE benchmarks info
        st.info("💡 World-class OEE benchmark: 85%+ (Availability 90%, Performance 95%, Quality 99.9%)")
        
        # OEE Trend Chart
        st.subheader("📈 OEE Trend Over Time")
        
        # Prepare data for trend chart
        daily_oee = []
        dates = []
        
        # Group by date and calculate daily OEE
        unique_dates = df['date'].dt.date.unique()
        for day in sorted(unique_dates):
            day_records = [r for r in records if pd.to_datetime(r['date']).date() == day]
            daily_oee.append(calculate_daily_oee(day_records))
            dates.append(day)
        
        # Create trend DataFrame
        trend_df = pd.DataFrame({
            'date': dates,
            'availability': [d['availability'] for d in daily_oee],
            'performance': [d['performance'] for d in daily_oee],
            'quality': [d['quality'] for d in daily_oee],
            'oee': [d['oee'] for d in daily_oee]
        })
        
        # Display trend chart
        if not trend_df.empty:
            chart_data = trend_df.set_index('date')
            st.line_chart(chart_data[['availability', 'performance', 'quality', 'oee']])
        
        # Detailed OEE Analysis
        st.subheader("🔍 Detailed OEE Analysis")
        
        tab1, tab2, tab3 = st.tabs(["Availability Analysis", "Performance Analysis", "Quality Analysis"])
        
        with tab1:
            st.write("**Downtime Analysis**")
            downtime_data = df[df['downtime_hours'] > 0]
            if not downtime_data.empty:
                downtime_by_reason = downtime_data.groupby('downtime_reason')['downtime_hours'].sum()
                st.bar_chart(downtime_by_reason)
            else:
                st.success("✅ No downtime recorded in this period!")
        
        with tab2:
            st.write("**Production vs Plan**")
            performance_data = df[['date', 'production_plan', 'production_actual']].copy()
            performance_data['date'] = pd.to_datetime(performance_data['date'])
            performance_data = performance_data.set_index('date')
            st.bar_chart(performance_data)
        
        with tab3:
            st.write("**Quality Metrics**")
            quality_data = df[['date', 'scrap']].copy()
            quality_data['date'] = pd.to_datetime(quality_data['date'])
            quality_data = quality_data.groupby(quality_data['date'].dt.date)['scrap'].sum()
            st.bar_chart(quality_data)
        
        # OEE by Department (if multiple departments selected)
        if department_filter == "All":
            st.subheader("🏭 OEE by Department")
            dept_oee = {}
            for dept in df['department'].unique():
                dept_records = [r for r in records if r['department'] == dept]
                dept_oee[dept] = calculate_daily_oee(dept_records)['oee']
            
            dept_df = pd.DataFrame(list(dept_oee.items()), columns=['Department', 'OEE'])
            st.bar_chart(dept_df.set_index('Department'))
        
        # Raw Data
        with st.expander("📋 View Detailed Records"):
            st.dataframe(df)
    
    else:
        st.info("No production records found for the selected period.")

# -------------------------
# Production Entry Page (Updated with Live OEE)
# -------------------------
def production_entry_page():
    update_activity()
    st.header(f"📋 {st.session_state.department} Daily Production Entry")
    
    # Initialize session state for OEE if not exists
    if 'oee_calc' not in st.session_state:
        st.session_state.oee_calc = {'availability': 0, 'performance': 0, 'quality': 0, 'oee': 0}
    
    with st.form("production_entry_form", clear_on_submit=True):
        col1, col2 = st.columns(2)
        
        with col1:
            entry_date = st.date_input("Date", value=datetime.today())
            shift = st.selectbox("Shift", ["Morning", "Evening", "Night"])
            manpower_avail = st.number_input("Manpower Available", min_value=0, step=1, value=0,
                                            help="Number of workers actually present")
            manpower_req = st.number_input("Manpower Required", min_value=0, step=1, value=0,
                                          help="Number of workers needed as per plan")
        
        with col2:
            prod_plan = st.number_input("Production Plan", min_value=0, step=1, value=0,
                                       help="Target production units for this shift")
            prod_actual = st.number_input("Production Actual", min_value=0, step=1, value=0,
                                         help="Actual production units achieved")
            scrap = st.number_input("Scrap / Rework", min_value=0, step=1, value=0,
                                   help="Number of defective units that need rework or scrap")
            downtime_hours = st.number_input("Downtime Hours", min_value=0.0, step=0.25, value=0.0,
                                            help="Total hours of downtime during shift")
        
        downtime_reason = st.text_input("Downtime Reason (if any)")
        notes = st.text_area("Notes / Remarks")
        
        # Live OEE Calculation
        if st.form_submit_button("Calculate Live OEE", type="secondary"):
            temp_record = {
                'production_plan': prod_plan,
                'production_actual': prod_actual,
                'scrap': scrap,
                'downtime_hours': downtime_hours
            }
            st.session_state.oee_calc = calculate_oee(temp_record)
        
        # Display OEE Metrics
        st.markdown("### 📊 Live OEE Calculation")
        oee_col1, oee_col2, oee_col3, oee_col4 = st.columns(4)
        
        with oee_col1:
            st.metric("Availability", f"{st.session_state.oee_calc['availability']}%")
        with oee_col2:
            st.metric("Performance", f"{st.session_state.oee_calc['performance']}%")
        with oee_col3:
            st.metric("Quality", f"{st.session_state.oee_calc['quality']}%")
        with oee_col4:
            st.metric("OEE", f"{st.session_state.oee_calc['oee']}%", 
                     delta=f"{st.session_state.oee_calc['oee'] - 85}%"
                     if st.session_state.oee_calc['oee'] != 0 else None,
                     delta_color="normal")
        
        submitted = st.form_submit_button("💾 Save Record")
        
        if submitted:
            update_activity()
            row = {
                "timestamp": datetime.utcnow().isoformat(),
                "date": entry_date.isoformat(),
                "shift": shift,
                "manpower_available": manpower_avail,
                "manpower_required": manpower_req,
                "production_plan": prod_plan,
                "production_actual": prod_actual,
                "scrap": scrap,
                "downtime_hours": downtime_hours,
                "downtime_reason": downtime_reason,
                "availability": st.session_state.oee_calc['availability'],
                "performance": st.session_state.oee_calc['performance'],
                "quality": st.session_state.oee_calc['quality'],
                "oee": st.session_state.oee_calc['oee'],
                "notes": notes,
                "entered_by": st.session_state.username,
                "department": st.session_state.department
            }
            
            try:
                response = supabase.table("production_metrics").insert(row).execute()
                if response.data:
                    log_audit_event(st.session_state.user_id, "create", "production_record", 
                                  response.data[0]["id"], 
                                  f"Created {st.session_state.department} record for {entry_date}")
                    st.success(f"✅ {st.session_state.department} record saved for {entry_date}, {shift} shift")
                    # Reset OEE calculation
                    st.session_state.oee_calc = {'availability': 0, 'performance': 0, 'quality': 0, 'oee': 0}
                else:
                    st.error("❌ Failed to save data.")
            except Exception as e:
                st.error(f"⚠️ Error: {e}")

# -------------------------
def quality_data_entry_page():
    update_activity()
    st.header("📊 QAHSE Quality Data Entry")

    # Inputs OUTSIDE form so they update live
    col1, col2 = st.columns(2)

    with col1:
        entry_date = st.date_input("Date", value=datetime.today())
        shift = st.selectbox("Shift", ["Morning", "Evening", "Night"])
        total_vehicles = st.number_input("Total Vehicles Inspected", min_value=0, step=1)
        passed_vehicles = st.number_input("Vehicles Passed", min_value=0, step=1)
        failed_vehicles = st.number_input("Vehicles Failed", min_value=0, step=1)

    with col2:
        total_defects = st.number_input("Total Defects Found", min_value=0, step=1)
        critical_defects = st.number_input("Critical Defects", min_value=0, step=1)
        major_defects = st.number_input("Major Defects", min_value=0, step=1)
        minor_defects = st.number_input("Minor Defects", min_value=0, step=1)

    defect_types = st.text_area("Major Defect Types (describe the main issues found)")
    corrective_actions = st.text_area("Corrective Actions Taken")

    # ✅ Live calculations (happen on every widget change)
    dpu = total_defects / total_vehicles if total_vehicles > 0 else 0
    fpy = (passed_vehicles / total_vehicles * 100) if total_vehicles > 0 else 0

    st.markdown("### Quality Metrics (Live)")
    st.metric("DPU (Defects Per Unit)", f"{dpu:.2f}")
    st.metric("First Pass Yield", f"{fpy:.1f}%")

    # Save button (manual submit)
    if st.button("💾 Save Quality Data"):
        quality_row = {
            "timestamp": datetime.utcnow().isoformat(),
            "date": entry_date.isoformat(),
            "shift": shift,
            "total_vehicles": total_vehicles,
            "passed_vehicles": passed_vehicles,
            "failed_vehicles": failed_vehicles,
            "total_defects": total_defects,
            "critical_defects": critical_defects,
            "major_defects": major_defects,
            "minor_defects": minor_defects,
            "dpu": dpu,
            "fpy": fpy,
            "defect_types": defect_types,
            "corrective_actions": corrective_actions,
            "entered_by": st.session_state.username,
            "department": "QAHSE"
        }

        try:
            response = supabase.table("quality_metrics").insert(quality_row).execute()
            if response.data:
                log_audit_event(
                    st.session_state.user_id,
                    "create",
                    "quality_record",
                    response.data[0]["id"],
                    f"Created QAHSE quality record for {entry_date}"
                )
                st.success(f"✅ QAHSE quality data saved for {entry_date}, {shift} shift")
            else:
                st.error("❌ Failed to save quality data.")
        except Exception as e:
            st.error(f"⚠️ Error: {e}")



# -------------------------
# Dashboard Page (Enhanced with OEE Analytics)
# -------------------------
def dashboard_page():
    update_activity()
    st.header("📊 Production Dashboard")
    
    # Date range filter with month selection option
    col1, col2, col3 = st.columns([1, 1, 2])
    
    with col1:
        date_range = st.selectbox("View by", 
                                ["Today", "This Week", "This Month", "Custom Range"])
    
    with col2:
        if date_range == "Custom Range":
            start_date = st.date_input("Start Date", value=date.today().replace(day=1))
            end_date = st.date_input("End Date", value=date.today())
        else:
            today = date.today()
            if date_range == "Today":
                start_date = today
                end_date = today
            elif date_range == "This Week":
                start_date = today - timedelta(days=today.weekday())
                end_date = start_date + timedelta(days=6)
            else:  # This Month
                start_date = today.replace(day=1)
                end_date = (start_date + timedelta(days=32)).replace(day=1) - timedelta(days=1)
    
    # Department filter
    departments = ["All"] + list(pd.DataFrame(get_all_users())["department"].dropna().unique())
    with col3:
        department_filter = st.selectbox("Filter by Department", departments)
    
    # Fetch production data
    records = get_production_metrics(start_date, end_date, department_filter)
    
    if records:
        df = pd.DataFrame(records)
        df["date"] = pd.to_datetime(df["date"], errors="coerce")
        
        # Calculate overall OEE for the period
        overall_oee = calculate_daily_oee(records)
        
        # KPI Metrics
        st.subheader("📈 Overall Equipment Effectiveness (OEE)")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Availability", f"{overall_oee['availability']}%")
        with col2:
            st.metric("Performance", f"{overall_oee['performance']}%")
        with col3:
            st.metric("Quality", f"{overall_oee['quality']}%")
        with col4:
            st.metric("Overall OEE", f"{overall_oee['oee']}%", 
                     delta_color="normal" if overall_oee['oee'] >= 85 else "inverse")
        
        # World-class OEE benchmarks info
        st.info("💡 World-class OEE benchmark: 85%+ (Availability 90%, Performance 95%, Quality 99.9%)")
        
        # OEE Trend Chart
        st.subheader("📈 OEE Trend Over Time")
        
        # Prepare data for trend chart
        daily_oee = []
        dates = []
        
        # Group by date and calculate daily OEE
        unique_dates = df['date'].dt.date.unique()
        for day in sorted(unique_dates):
            day_records = [r for r in records if pd.to_datetime(r['date']).date() == day]
            daily_oee.append(calculate_daily_oee(day_records))
            dates.append(day)
        
        # Create trend DataFrame
        trend_df = pd.DataFrame({
            'date': dates,
            'availability': [d['availability'] for d in daily_oee],
            'performance': [d['performance'] for d in daily_oee],
            'quality': [d['quality'] for d in daily_oee],
            'oee': [d['oee'] for d in daily_oee]
        })
        
        # Display trend chart
        if not trend_df.empty:
            chart_data = trend_df.set_index('date')
            st.line_chart(chart_data[['availability', 'performance', 'quality', 'oee']])
        
        # Detailed OEE Analysis
        st.subheader("🔍 Detailed OEE Analysis")
        
        tab1, tab2, tab3 = st.tabs(["Availability Analysis", "Performance Analysis", "Quality Analysis"])
        
        with tab1:
            st.write("**Downtime Analysis**")
            downtime_data = df[df['downtime_hours'] > 0]
            if not downtime_data.empty:
                downtime_by_reason = downtime_data.groupby('downtime_reason')['downtime_hours'].sum()
                st.bar_chart(downtime_by_reason)
            else:
                st.success("✅ No downtime recorded in this period!")
        
        with tab2:
            st.write("**Production vs Plan**")
            performance_data = df[['date', 'production_plan', 'production_actual']].copy()
            performance_data['date'] = pd.to_datetime(performance_data['date'])
            performance_data = performance_data.set_index('date')
            st.bar_chart(performance_data)
        
        with tab3:
            st.write("**Quality Metrics**")
            quality_data = df[['date', 'scrap']].copy()
            quality_data['date'] = pd.to_datetime(quality_data['date'])
            quality_data = quality_data.groupby(quality_data['date'].dt.date)['scrap'].sum()
            st.bar_chart(quality_data)
        
        # OEE by Department (if multiple departments selected)
        if department_filter == "All":
            st.subheader("🏭 OEE by Department")
            dept_oee = {}
            for dept in df['department'].unique():
                dept_records = [r for r in records if r['department'] == dept]
                dept_oee[dept] = calculate_daily_oee(dept_records)['oee']
            
            dept_df = pd.DataFrame(list(dept_oee.items()), columns=['Department', 'OEE'])
            st.bar_chart(dept_df.set_index('Department'))
        
        # Raw Data
        with st.expander("📋 View Detailed Records"):
            st.dataframe(df)
    
    else:
        st.info("No production records found for the selected period.")
# -------------------------
# Access Request Page
# -------------------------
def access_request_page():
    update_activity()
    st.header("🔓 Request Access")
    
    if st.session_state.role == "viewer":
        st.info("You currently have view-only access. Request higher privileges below.")
        
        with st.form("access_request_form"):
            requested_role = st.selectbox("Requested Role", ["supervisor", "admin"])
            reason = st.text_area("Reason for access request")
            
            if st.form_submit_button("Submit Request"):
                update_activity()
                if create_access_request(st.session_state.username, requested_role, reason):
                    st.success("Access request submitted! An admin will review your request.")
                else:
                    st.error("Failed to submit request")
    else:
        st.success("You already have elevated privileges!")

# -------------------------
# Admin Pages
# -------------------------
def user_management_page():
    update_activity()
    st.header("👥 User Management")
    
    # Tab interface for different management sections
    tab1, tab2 = st.tabs(["🔄 Pending Approvals", "👤 Manage Existing Users"])
    
    with tab1:
        st.subheader("Users Waiting for Approval")
        pending_users = get_pending_users()
        
        if pending_users:
            for user in pending_users:
                with st.expander(f"Pending: {user['username']} - {user.get('department', 'No department')}"):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.write(f"**Username:** {user['username']}")
                        st.write(f"**Department:** {user.get('department', 'Not set')}")
                        st.write(f"**Requested Role:** {user.get('role', 'viewer')}")
                        st.write(f"**Created:** {pd.to_datetime(user['created_at']).strftime('%Y-%m-%d %H:%M') if user.get('created_at') else 'N/A'}")
                    
                    with col2:
                        if st.button("✅ Approve User", key=f"approve_{user['id']}"):
                            update_activity()
                            if approve_user(user['id']):
                                st.success(f"✅ {user['username']} approved!")
                                log_audit_event(st.session_state.user_id, "user_approved", "user", user['id'], f"Approved user {user['username']}")
                                time.sleep(1)
                                st.rerun()
                            else:
                                st.error("Failed to approve user")
                        
                        if st.button("❌ Reject User", key=f"reject_{user['id']}"):
                            update_activity()
                            try:
                                # Delete the user who was rejected
                                response = supabase.table("users").delete().eq("id", user['id']).execute()
                                if response.data:
                                    st.success(f"❌ {user['username']} rejected and removed!")
                                    log_audit_event(st.session_state.user_id, "user_rejected", "user", user['id'], f"Rejected user {user['username']}")
                                    time.sleep(1)
                                    st.rerun()
                                else:
                                    st.error("Failed to reject user")
                            except Exception as e:
                                st.error(f"Error rejecting user: {str(e)}")
        else:
            st.success("✅ No pending user approvals!")
    
    with tab2:
        st.subheader("Manage Existing Users")
        users = get_all_users()
        approved_users = [user for user in users if user['approved']]
        
        if approved_users:
            for user in approved_users:
                with st.expander(f"User: {user['username']} - {user['role']} ({'✅ Approved' if user['approved'] else '⏳ Pending'})"):
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        st.write(f"**Department:** {user.get('department', 'Not set')}")
                        st.write(f"**Last Login:** {user.get('last_login', 'Never')}")
                        st.write(f"**Status:** {'🟢 Online' if user.get('is_online') else '🔴 Offline'}")
                    
                    with col2:
                        if user['username'] != GOD_ADMIN_USERNAME:
                            new_role = st.selectbox("Role", ["viewer", "supervisor", "admin"], 
                                                  index=["viewer", "supervisor", "admin"].index(user['role']),
                                                  key=f"role_{user['id']}")
                            new_dept = st.selectbox("Department", ["Assembly Shop", "Paint Shop", "Weld Shop", "QAHSE", "PDI"], 
                                                  index=0 if not user.get('department') else ["Assembly Shop", "Paint Shop", "Weld Shop", "QAHSE", "PDI"].index(user['department']),
                                                  key=f"dept_{user['id']}")
                    
                    with col3:
                        if user['username'] != GOD_ADMIN_USERNAME:
                            if st.button("Update User", key=f"update_{user['id']}"):
                                update_activity()
                                update_user_role(user['id'], new_role)
                                update_user_department(user['id'], new_dept)
                                st.success("User updated!")
                                log_audit_event(st.session_state.user_id, "user_updated", "user", user['id'], f"Updated {user['username']} to {new_role} in {new_dept}")
                                time.sleep(1)
                                st.rerun()
                            
                            if st.button("Reset Password", key=f"pwd_{user['id']}"):
                                update_activity()
                                if reset_user_password(user['id'], "TempPassword123!"):
                                    st.success("Password reset to 'TempPassword123!'")
                                    log_audit_event(st.session_state.user_id, "password_reset", "user", user['id'], f"Reset password for {user['username']}")
                                else:
                                    st.error("Failed to reset password")
                            
                            if st.button("Force Logout", key=f"logout_{user['id']}"):
                                update_activity()
                                if set_user_online_status(user['id'], False):
                                    st.success("User logged out forcefully")
                                    log_audit_event(st.session_state.user_id, "force_logout", "user", user['id'], f"Force logged out {user['username']}")
                                else:
                                    st.error("Failed to force logout")
        
        st.subheader("Create New User")
        with st.form("create_user_form"):
            new_username = st.text_input("Username")
            new_password = st.text_input("Password", type="password")
            new_role = st.selectbox("Role", ["viewer", "supervisor", "admin"])
            new_department = st.selectbox("Department", ["Assembly Shop", "Paint Shop", "Weld Shop", "QAHSE", "PDI"])
            
            if st.form_submit_button("Create User"):
                update_activity()
                if create_user(new_username, new_password, new_role, True, new_department):
                    st.success("User created successfully!")
                    log_audit_event(st.session_state.user_id, "user_created", "user", "N/A", f"Created user {new_username} as {new_role}")
                    time.sleep(1)
                    st.rerun()
                else:
                    st.error("Failed to create user")
def access_requests_page():
    update_activity()
    st.header("📋 Pending Access Requests")
    
    # Tab interface for different request types
    tab1, tab2 = st.tabs(["Role Access Requests", "Password Change Requests"])
    
    with tab1:
        st.subheader("Role Access Requests")
        requests = get_pending_requests()
        if requests:
            for req in requests:
                with st.expander(f"Role Request from {req['username']} for {req['requested_role']} role"):
                    st.write(f"**Reason:** {req['reason']}")
                    st.write(f"**Requested:** {req['requested_at']}")
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        if st.button("✅ Approve", key=f"approve_role_{req['id']}"):
                            update_activity()
                            user = get_user(req['username'])
                            if user and update_user_role(user['id'], req['requested_role']):
                                approve_user(user['id'])
                                update_request_status(req['id'], "approved", st.session_state.username)
                                log_audit_event(st.session_state.user_id, "approve_request", "access_request", req['id'], f"Approved {req['requested_role']} role for {req['username']}")
                                st.success("Request approved!")
                                time.sleep(1)
                                st.rerun()
                    with col2:
                        if st.button("❌ Deny", key=f"deny_role_{req['id']}"):
                            update_activity()
                            update_request_status(req['id'], "denied", st.session_state.username)
                            log_audit_event(st.session_state.user_id, "deny_request", "access_request", req['id'], f"Denied {req['requested_role']} role for {req['username']}")
                            st.success("Request denied!")
                            time.sleep(1)
                            st.rerun()
        else:
            st.success("No pending role access requests!")
    
    with tab2:
        st.subheader("Password Change Requests")
        password_requests = get_password_change_requests()
        if password_requests:
            for req in password_requests:
                with st.expander(f"Password Change Request from {req['username']}"):
                    st.write(f"**Requested:** {req['requested_at']}")
                    
                    col3, col4 = st.columns(2)
                    with col3:
                        if st.button("✅ Approve Password Change", key=f"approve_pwd_{req['id']}"):
                            update_activity()
                            if approve_password_change(req['id'], st.session_state.username):
                                update_password_request_status(req['id'], "approved", st.session_state.username)
                                log_audit_event(st.session_state.user_id, "approve_password", "user", "N/A", f"Approved password change for {req['username']}")
                                st.success("Password change approved!")
                                time.sleep(1)
                                st.rerun()
                            else:
                                st.error("Failed to approve password change")
                    with col4:
                        if st.button("❌ Deny Password Change", key=f"deny_pwd_{req['id']}"):
                            update_activity()
                            update_password_request_status(req['id'], "denied", st.session_state.username)
                            log_audit_event(st.session_state.user_id, "deny_password", "user", "N/A", f"Denied password change for {req['username']}")
                            st.success("Password change denied!")
                            time.sleep(1)
                            st.rerun()
        else:
            st.success("No pending password change requests!")

def production_control_page():
    update_activity()
    st.header("⚙️ Production Data Control")
    
    # Fetch production records
    records = get_recent_production_records(50)
    
    if records:
        for record in records:
            editable = can_edit_record(record['date'])
            status = "🟢 Editable" if editable else "🔴 Locked (older than 7 days)"
            
            with st.expander(f"{record['date']} - {record['shift']} - {record['entered_by']} - {record['department']} - {status}"):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write(f"**Production:** {record['production_actual']}/{record['production_plan']}")
                    st.write(f"**Manpower:** {record['manpower_available']}/{record['manpower_required']}")
                    st.write(f"**OEE:** {record['availability']}% A, {record['performance']}% P, {record['quality']}% Q")
                
                with col2:
                    st.write(f"**Scrap:** {record['scrap']}")
                    st.write(f"**Downtime:** {record['downtime_hours']}h - {record['downtime_reason']}")
                    st.write(f"**Entered by:** {record['entered_by']}")
                    st.write(f"**Department:** {record['department']}")
                
                if editable and st.session_state.role == "admin":
                    if st.button("Edit Record", key=f"edit_{record['id']}"):
                        update_activity()
                        st.session_state.editing_record = record
                        st.rerun()
                    
                    if st.button("Delete Record", key=f"delete_{record['id']}"):
                        update_activity()
                        try:
                            supabase.table("production_metrics").delete().eq("id", record['id']).execute()
                            log_audit_event(st.session_state.user_id, "delete", "production_record", record['id'], f"Deleted {record['department']} record from {record['date']}")
                            st.success("Record deleted!")
                            time.sleep(1)
                            st.rerun()
                        except:
                            st.error("Failed to delete record")
                elif not editable:
                    st.warning("This record is locked and cannot be modified (older than 7 days)")
    else:
        st.info("No production records found.")

def audit_log_page():
    update_activity()
    st.header("📊 Audit Log")
    
    logs = get_audit_logs(100)
    if logs:
        log_df = pd.DataFrame(logs)
        st.dataframe(log_df[['timestamp', 'username', 'action', 'target_type', 'details']])
    else:
        st.info("No audit logs found.")

def system_monitor_page():
    update_activity()
    st.header("📡 System Monitor")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🟢 Online Users")
        online_users = get_online_users()
        if online_users:
            for user in online_users:
                st.write(f"**{user['username']}** ({user['role']}) - {user['department']}")
        else:
            st.info("No users online")
    
    with col2:
        st.subheader("📈 System Stats")
        users = get_all_users()
        record_counts = get_record_counts()
        
        st.metric("Total Users", len(users))
        st.metric("Online Users", len(online_users))
        st.metric("Production Records", record_counts["production"])
        st.metric("Quality Records", record_counts["quality"])

# -------------------------
# Main App Logic
# -------------------------
def main():
    # Setup god admin on first run
    try:
        setup_god_admin()
    except Exception as e:
        st.error(f"Failed to setup God Admin: {str(e)}")
    
    if not st.session_state.authenticated:
        auth_page()
    else:
        try:
            # Check for auto logout
            auto_logout_check()
            
            # Update user activity every minute
            if time.time() - st.session_state.last_activity_update > 60:
                set_user_online_status(st.session_state.user_id, True)
                st.session_state.last_activity_update = time.time()
            
            selected_page = show_sidebar()
            
            if selected_page == "Dashboard":
                dashboard_page()
            elif selected_page == "Profile":
                profile_page()
            elif selected_page == "Production Entry":
                production_entry_page()
            elif selected_page == "Quality Data Entry":
                quality_data_entry_page()
            elif selected_page == "Request Access":
                access_request_page()
            elif selected_page == "User Management":
                user_management_page()
            elif selected_page == "Access Requests":
                access_requests_page()
            elif selected_page == "Production Control":
                production_control_page()
            elif selected_page == "Audit Log":
                audit_log_page()
            elif selected_page == "System Monitor":
                system_monitor_page()
                
        except Exception as e:
            st.error(f"An error occurred: {str(e)}")
            st.info("Please try refreshing the page or contact support if the issue persists.")

if __name__ == "__main__":
    main()
