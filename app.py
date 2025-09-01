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

# -------------------------
# Security Functions (From First App)
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
# Database Functions (Enhanced with Error Handling)
# -------------------------
def get_user(username):
    try:
        response = supabase.table("users").select("*").eq("username", username).execute()
        return response.data[0] if response.data else None
    except Exception as e:
        st.error(f"Error fetching user: {str(e)}")
        return None

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

def get_all_users():
    try:
        response = supabase.table("users").select("*").execute()
        return response.data
    except Exception as e:
        st.error(f"Error fetching users: {str(e)}")
        return []

# Update all other database functions with similar try-catch blocks...
# For example:

def set_user_online_status(user_id, is_online):
    try:
        response = supabase.table("users").update({
            "is_online": is_online,
            "last_activity": datetime.utcnow().isoformat()
        }).eq("id", user_id).execute()
        return True
    except Exception as e:
        st.error(f"Error updating online status: {str(e)}")
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

# -------------------------
# Pre-defined God Admin (Secure Version)
# -------------------------
GOD_ADMIN_USERNAME = "admin"
GOD_ADMIN_PASSWORD = st.secrets.get("GOD_ADMIN_PASSWORD", "admin123")  # Fallback to default

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
                st.warning("God Admin account might already exist or there was an issue creating it.")
        else:
            # Sync password if changed in secrets
            if not check_password(GOD_ADMIN_PASSWORD, existing_admin["password_hash"]):
                response = supabase.table("users").update({
                    "password_hash": hashed_password
                }).eq("username", GOD_ADMIN_USERNAME).execute()
                if response.data:
                    st.warning("God Admin password updated!")
                else:
                    st.warning("Could not update God Admin password.")
    except Exception as e:
        st.error(f"Error setting up God Admin: {str(e)}")
        # Don't crash the app, just log the error
        print(f"God Admin setup error: {e}")


# -------------------------
# Login/Registration Page (Secure Version)
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
# Navigation Sidebar (With Security)
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
            set_user_online_status(st.session_state.user_id, False)
            log_audit_event(st.session_state.user_id, "logout", "system", "N/A", "User logged out")
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()
    
    return selected_page

# -------------------------
# Profile Page (Secure Version)
# -------------------------
def profile_page():
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
            st.write(f"**Member since:** {pd.to_datetime(user['created_at']).strftime('%Y-%m-%d')}")
            st.write(f"**Last Activity:** {pd.to_datetime(user.get('last_activity', 'Never')).strftime('%Y-%m-%d %H:%M')}")
        
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
# Production Entry Page (Secure)
# -------------------------
def production_entry_page():
    update_activity()
    st.header(f"📋 {st.session_state.department} Daily Production Entry")
    
    with st.form("production_entry_form", clear_on_submit=True):
        col1, col2 = st.columns(2)
        
        with col1:
            entry_date = st.date_input("Date", value=datetime.today())
            shift = st.selectbox("Shift", ["Morning", "Evening", "Night"])
            manpower_avail = st.number_input("Manpower Available", min_value=0, step=1)
            manpower_req = st.number_input("Manpower Required", min_value=0, step=1)
        
        with col2:
            prod_plan = st.number_input("Production Plan", min_value=0, step=1)
            prod_actual = st.number_input("Production Actual", min_value=0, step=1)
            scrap = st.number_input("Scrap / Rework", min_value=0, step=1)
            downtime_hours = st.number_input("Downtime Hours", min_value=0.0, step=0.25)
        
        downtime_reason = st.text_input("Downtime Reason (if any)")
        
        st.markdown("### OEE Components")
        avail_col, perf_col, qual_col = st.columns(3)
        with avail_col:
            availability = st.number_input("Availability (%)", min_value=0, max_value=100, value=85, step=1)
        with perf_col:
            performance = st.number_input("Performance (%)", min_value=0, max_value=100, value=90, step=1)
        with qual_col:
            quality = st.number_input("Quality (%)", min_value=0, max_value=100, value=95, step=1)
        
        notes = st.text_area("Notes / Remarks")
        
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
                "availability": availability,
                "performance": performance,
                "quality": quality,
                "notes": notes,
                "entered_by": st.session_state.username,
                "department": st.session_state.department
            }
            
            try:
                response = supabase.table("production_metrics").insert(row).execute()
                if response.data:
                    log_audit_event(st.session_state.user_id, "create", "production_record", response.data[0]["id"], f"Created {st.session_state.department} record for {entry_date}")
                    st.success(f"✅ {st.session_state.department} record saved for {entry_date}, {shift} shift")
                else:
                    st.error("❌ Failed to save data.")
            except Exception as e:
                st.error(f"⚠️ Error: {e}")

# -------------------------
# Quality Data Entry Page (Secure)
# -------------------------
def quality_data_entry_page():
    update_activity()
    st.header("📊 QAHSE Quality Data Entry")
    
    with st.form("quality_entry_form", clear_on_submit=True):
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
        
        # Calculate DPU (Defects Per Unit)
        dpu = total_defects / total_vehicles if total_vehicles > 0 else 0
        
        st.markdown("### Quality Metrics")
        st.metric("DPU (Defects Per Unit)", f"{dpu:.2f}")
        st.metric("First Pass Yield", f"{(passed_vehicles/total_vehicles*100):.1f}%" if total_vehicles > 0 else "0%")
        
        defect_types = st.text_area("Major Defect Types (describe the main issues found)")
        corrective_actions = st.text_area("Corrective Actions Taken")
        
        submitted = st.form_submit_button("💾 Save Quality Data")
        
        if submitted:
            update_activity()
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
                "defect_types": defect_types,
                "corrective_actions": corrective_actions,
                "entered_by": st.session_state.username,
                "department": "QAHSE"
            }
            
            try:
                response = supabase.table("quality_metrics").insert(quality_row).execute()
                if response.data:
                    log_audit_event(st.session_state.user_id, "create", "quality_record", response.data[0]["id"], f"Created QAHSE quality record for {entry_date}")
                    st.success(f"✅ QAHSE quality data saved for {entry_date}, {shift} shift")
                else:
                    st.error("❌ Failed to save quality data.")
            except Exception as e:
                st.error(f"⚠️ Error: {e}")

# -------------------------
# Dashboard Page (With Security)
# -------------------------
def dashboard_page():
    update_activity()
    st.header("📊 Production Dashboard")
    
    # Date filters
    col1, col2 = st.columns(2)
    with col1:
        start_date = st.date_input("Start Date", value=date.today().replace(day=1))
    with col2:
        end_date = st.date_input("End Date", value=date.today())
    
    # Department filter
    departments = ["All"] + list(pd.DataFrame(get_all_users())["department"].dropna().unique())
    department_filter = st.selectbox("Filter by Department", departments)
    
    # Fetch production data
    try:
        query = supabase.table("production_metrics").select("*")
        if department_filter and department_filter != "All":
            query = query.eq("department", department_filter)
        records = query.execute().data
    except Exception as e:
        st.error(f"⚠️ Could not fetch production data: {e}")
        records = []
    
    # Fetch quality data
    try:
        quality_query = supabase.table("quality_metrics").select("*")
        if department_filter and department_filter != "All":
            quality_query = quality_query.eq("department", department_filter)
        quality_records = quality_query.execute().data
    except:
        quality_records = []
    
    if records:
        df = pd.DataFrame(records)
        df["date"] = pd.to_datetime(df["date"], errors="coerce")
        
        # Filter by date range
        mask = (df['date'].dt.date >= start_date) & (df['date'].dt.date <= end_date)
        df_filtered = df.loc[mask]
        
        if not df_filtered.empty:
            # KPI Metrics
            st.subheader("📈 Production Performance Indicators")
            col1, col2, col3, col4 = st.columns(4)
            
            total_planned = df_filtered["production_plan"].sum()
            total_actual = df_filtered["production_actual"].sum()
            avg_avail = df_filtered["availability"].mean()
            avg_perf = df_filtered["performance"].mean()
            avg_qual = df_filtered["quality"].mean()
            monthly_oee = (avg_avail/100) * (avg_perf/100) * (avg_qual/100) * 100
            
            with col1:
                st.metric("Total Planned", f"{total_planned:,}")
            with col2:
                st.metric("Total Actual", f"{total_actual:,}", f"{(total_actual-total_planned):+,}")
            with col3:
                st.metric("Avg Availability", f"{avg_avail:.1f}%")
            with col4:
                st.metric("OEE", f"{monthly_oee:.1f}%")
            
            # Production Charts
            st.subheader("📊 Production Trends")
            tab1, tab2, tab3 = st.tabs(["OEE Trend", "Production vs Plan", "Downtime Analysis"])
            
            with tab1:
                oee_data = df_filtered[['date', 'availability', 'performance', 'quality']].set_index('date')
                st.line_chart(oee_data)
            
            with tab2:
                prod_data = df_filtered[['date', 'production_plan', 'production_actual']].set_index('date')
                st.bar_chart(prod_data)
            
            with tab3:
                if not df_filtered['downtime_reason'].empty:
                    downtime_data = df_filtered[df_filtered['downtime_reason'].notnull()]
                    if not downtime_data.empty:
                        st.dataframe(downtime_data[['date', 'shift', 'downtime_reason', 'downtime_hours']])
                    else:
                        st.success("✅ No downtime recorded in this period!")
                else:
                    st.info("No downtime data available.")
        
        else:
            st.info("No production records found for the selected date range.")
    else:
        st.info("No production records found yet.")
    
    # Quality Data Section
    if quality_records:
        quality_df = pd.DataFrame(quality_records)
        quality_df["date"] = pd.to_datetime(quality_df["date"], errors="coerce")
        
        # Filter by date range
        quality_mask = (quality_df['date'].dt.date >= start_date) & (quality_df['date'].dt.date <= end_date)
        quality_filtered = quality_df.loc[quality_mask]
        
        if not quality_filtered.empty:
            st.subheader("📈 Quality Performance Indicators")
            q_col1, q_col2, q_col3, q_col4 = st.columns(4)
            
            total_inspected = quality_filtered["total_vehicles"].sum()
            total_passed = quality_filtered["passed_vehicles"].sum()
            avg_dpu = quality_filtered["dpu"].mean()
            first_pass_yield = (total_passed / total_inspected * 100) if total_inspected > 0 else 0
            
            with q_col1:
                st.metric("Total Inspected", f"{total_inspected:,}")
            with q_col2:
                st.metric("Passed Vehicles", f"{total_passed:,}")
            with q_col3:
                st.metric("Avg DPU", f"{avg_dpu:.2f}")
            with q_col4:
                st.metric("First Pass Yield", f"{first_pass_yield:.1f}%")
            
            # Quality Charts
            st.subheader("📊 Quality Trends")
            q_tab1, q_tab2 = st.tabs(["DPU Trend", "Defect Analysis"])
            
            with q_tab1:
                dpu_data = quality_filtered[['date', 'dpu']].set_index('date')
                st.line_chart(dpu_data)
            
            with q_tab2:
                defect_data = quality_filtered[['date', 'critical_defects', 'major_defects', 'minor_defects']].set_index('date')
                st.bar_chart(defect_data)
    
    # Raw Data
    with st.expander("📋 View Raw Data"):
        if records:
            st.write("### Production Data")
            st.dataframe(df_filtered if 'df_filtered' in locals() else pd.DataFrame(records))
        if quality_records:
            st.write("### Quality Data")
            st.dataframe(quality_filtered if 'quality_filtered' in locals() else pd.DataFrame(quality_records))

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
# Admin Pages (Secure)
# -------------------------
def user_management_page():
    update_activity()
    st.header("👥 User Management")
    
    users = get_all_users()
    if users:
        for user in users:
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
                    time.sleep(1)
                    st.rerun()
                else:
                    st.error("Failed to create user")
    
    else:
        st.info("No users found.")

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
    try:
        records = supabase.table("production_metrics").select("*").order("date", desc=True).limit(50).execute().data
    except:
        records = []
    
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
        records = supabase.table("production_metrics").select("id", count="exact").execute()
        quality_records = supabase.table("quality_metrics").select("id", count="exact").execute()
        
        st.metric("Total Users", len(users))
        st.metric("Online Users", len(online_users))
        st.metric("Production Records", records.count if records else 0)
        st.metric("Quality Records", quality_records.count if quality_records else 0)

# -------------------------
# Main App Logic (With Error Handling)
# -------------------------
def main():
    # Setup god admin on first run (with error handling)
    try:
        setup_god_admin()
    except Exception as e:
        st.error(f"Failed to setup God Admin: {str(e)}")
        # Continue anyway - the app might still work
    
    if not st.session_state.authenticated:
        auth_page()
    else:
        try:
            # Check for auto logout
            auto_logout_check()
            
            # Update user activity every minute
            if 'last_activity_update' not in st.session_state or time.time() - st.session_state.last_activity_update > 60:
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
