import streamlit as st
from supabase import create_client, Client
import pandas as pd
import bcrypt
from datetime import datetime, timedelta

# ------------------------
# CONFIG
# ------------------------
st.set_page_config(page_title="Production Dashboard", layout="wide")

SUPABASE_URL = st.secrets["SUPABASE_URL"]
SUPABASE_KEY = st.secrets["SUPABASE_KEY"]
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

GOD_ADMIN_PASSWORD = st.secrets["GOD_ADMIN_PASSWORD"]  # stored in st.secrets, not hardcoded
MAX_IDLE_MINUTES = 30

# ------------------------
# HELPERS
# ------------------------
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def check_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())

def log_action(user_id, action, ip="N/A"):
    supabase.table("audit_logs").insert({
        "user_id": user_id,
        "action": action,
        "ip_address": ip
    }).execute()

def set_user_online_status(user_id, status: bool):
    supabase.table("users").update({"is_online": status}).eq("id", user_id).execute()

def auto_logout_check():
    if "last_activity" in st.session_state:
        idle_time = datetime.utcnow() - datetime.fromisoformat(st.session_state.last_activity)
        if idle_time > timedelta(minutes=MAX_IDLE_MINUTES):
            set_user_online_status(st.session_state.user_id, False)
            st.warning("You were logged out due to inactivity.")
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()

# ------------------------
# INIT GOD ADMIN
# ------------------------
def init_god_admin():
    """Ensure god_admin exists in Supabase and stays in sync with st.secrets"""
    res = supabase.table("users").select("*").eq("username", "god_admin").execute()

    if not res.data:
        hashed = hash_password(GOD_ADMIN_PASSWORD)
        supabase.table("users").insert({
            "username": "god_admin",
            "password_hash": hashed,
            "role": "god_admin",
            "is_online": False
        }).execute()
        st.info("👑 God Admin account created in Supabase.")
    else:
        # Sync password if changed in secrets
        current_hash = res.data[0]["password_hash"]
        if not check_password(GOD_ADMIN_PASSWORD, current_hash):
            supabase.table("users").update({
                "password_hash": hash_password(GOD_ADMIN_PASSWORD)
            }).eq("username", "god_admin").execute()
            st.warning("🔄 God Admin password updated in Supabase.")

# ------------------------
# AUTH
# ------------------------
def auth_page():
    st.title("🔑 Login")

    choice = st.radio("Choose option", ["Login", "Sign Up", "Request Role Change", "Request Password Change"])

    if choice == "Sign Up":
        new_user = st.text_input("Username")
        new_pass = st.text_input("Password", type="password")
        if st.button("Create Account"):
            hashed = hash_password(new_pass)
            supabase.table("users").insert({
                "username": new_user,
                "password_hash": hashed,
                "role": "operator",
                "is_online": False
            }).execute()
            st.success("✅ Account created successfully!")

    elif choice == "Login":
        user = st.text_input("Username")
        pw = st.text_input("Password", type="password")
        if st.button("Login"):
            res = supabase.table("users").select("*").eq("username", user).execute()
            if res.data and check_password(pw, res.data[0]["password_hash"]):
                st.session_state.user_id = res.data[0]["id"]
                st.session_state.username = res.data[0]["username"]
                st.session_state.role = res.data[0]["role"]
                st.session_state.last_activity = datetime.utcnow().isoformat()
                set_user_online_status(st.session_state.user_id, True)
                log_action(st.session_state.user_id, "Login")
                st.success("✅ Logged in successfully!")
                st.rerun()
            else:
                st.error("❌ Invalid credentials")

    elif choice == "Request Role Change":
        user = st.text_input("Username")
        req_role = st.selectbox("Request role", ["quality", "supervisor", "admin"])
        if st.button("Submit"):
            supabase.table("access_requests").insert({
                "username": user,
                "requested_role": req_role,
                "status": "pending"
            }).execute()
            st.success("✅ Request submitted")

    elif choice == "Request Password Change":
        user = st.text_input("Username")
        new_pw = st.text_input("New Password", type="password")
        if st.button("Submit"):
            hashed = hash_password(new_pw)
            supabase.table("password_requests").insert({
                "username": user,
                "new_password_hash": hashed,
                "status": "pending"
            }).execute()
            st.success("✅ Password change request submitted")

# ------------------------
# DASHBOARD
# ------------------------
def dashboard_page():
    st.title("📊 Production Dashboard")

    col1, col2 = st.columns(2)
    with col1:
        start_date = st.date_input("Start date", datetime.today() - timedelta(days=7))
    with col2:
        end_date = st.date_input("End date", datetime.today())

    prod = supabase.table("production_metrics").select("*")\
        .gte("date", str(start_date)).lte("date", str(end_date)).execute()
    qual = supabase.table("quality_metrics").select("*")\
        .gte("date", str(start_date)).lte("date", str(end_date)).execute()

    df_prod = pd.DataFrame(prod.data)
    df_qual = pd.DataFrame(qual.data)

    if not df_prod.empty:
        st.subheader("📦 Production Summary")
        st.metric("Total Parts", df_prod["produced_parts"].sum())
        st.line_chart(df_prod.set_index("date")["produced_parts"])
    else:
        st.info("No production data")

    if not df_qual.empty:
        st.subheader("🛠 Quality Summary")
        st.metric("Total Defects", df_qual["defects"].sum())
        st.line_chart(df_qual.set_index("date")["defects"])
    else:
        st.info("No quality data")

# ------------------------
# ROLE PAGES
# ------------------------
def operator_page():
    st.header("👷 Operator - Enter Production Data")
    date = st.date_input("Date", datetime.today())
    shift = st.selectbox("Shift", ["Morning", "Evening", "Night"])
    parts = st.number_input("Produced Parts", min_value=0)
    if st.button("Submit"):
        supabase.table("production_metrics").insert({
            "date": str(date),
            "shift": shift,
            "produced_parts": parts,
            "operator": st.session_state.username
        }).execute()
        log_action(st.session_state.user_id, "Submitted production data")
        st.success("✅ Data submitted")

def quality_page():
    st.header("🔍 Quality Inspector - Enter Defects")
    date = st.date_input("Date", datetime.today())
    shift = st.selectbox("Shift", ["Morning", "Evening", "Night"])
    defects = st.number_input("Defects", min_value=0)
    if st.button("Submit"):
        supabase.table("quality_metrics").insert({
            "date": str(date),
            "shift": shift,
            "defects": defects,
            "inspector": st.session_state.username
        }).execute()
        log_action(st.session_state.user_id, "Submitted quality data")
        st.success("✅ Data submitted")

def supervisor_page():
    st.header("🧑‍💼 Supervisor - Dashboard Access")
    dashboard_page()

def admin_page():
    st.header("🛠 Admin Panel")

    st.subheader("Approve Role Requests")
    reqs = supabase.table("access_requests").select("*").eq("status", "pending").execute()
    for r in reqs.data:
        st.write(r)
        if st.button(f"Approve {r['username']}", key=f"role-{r['id']}"):
            supabase.table("users").update({"role": r["requested_role"]}).eq("username", r["username"]).execute()
            supabase.table("access_requests").update({"status": "approved"}).eq("id", r["id"]).execute()
            st.success(f"✅ {r['username']} promoted to {r['requested_role']}")

    st.subheader("Approve Password Requests")
    preqs = supabase.table("password_requests").select("*").eq("status", "pending").execute()
    for r in preqs.data:
        st.write(r)
        if st.button(f"Approve password for {r['username']}", key=f"pw-{r['id']}"):
            supabase.table("users").update({"password_hash": r["new_password_hash"]}).eq("username", r["username"]).execute()
            supabase.table("password_requests").update({"status": "approved"}).eq("id", r["id"]).execute()
            st.success(f"✅ Password updated for {r['username']}")

def god_admin_page():
    st.header("👑 God Admin")
    st.write("Full DB access")
    if st.button("Reset System"):
        for table in ["users", "production_metrics", "quality_metrics", "access_requests", "password_requests", "audit_logs"]:
            supabase.table(table).delete().neq("id", "000").execute()
        st.success("✅ System reset")

# ------------------------
# MAIN
# ------------------------
def main():
    if "username" not in st.session_state:
        auth_page()
        return

    auto_logout_check()

    st.sidebar.title(f"Welcome, {st.session_state.username}")
    if st.sidebar.button("Logout"):
        if "user_id" in st.session_state:
            set_user_online_status(st.session_state.user_id, False)
            log_action(st.session_state.user_id, "Logout")
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.rerun()

    role = st.session_state.role
    if role == "operator":
        operator_page()
    elif role == "quality":
        quality_page()
    elif role == "supervisor":
        supervisor_page()
    elif role == "admin":
        admin_page()
    elif role == "god_admin":
        god_admin_page()
    else:
        st.error("Unknown role")

if __name__ == "__main__":
    init_god_admin()  # auto-create or update god_admin
    main()
