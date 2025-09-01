# production_line.py
import streamlit as st
import pandas as pd
from datetime import datetime
from supabase import create_client
import time

# Database functions for production line
def get_production_line_data(supabase):
    """Get current production line status"""
    try:
        response = supabase.table("production_line").select("*").order("station_order").execute()
        return response.data
    except:
        # If table doesn't exist, return empty list
        return []

def update_vehicle_station(supabase, vehicle_id, new_station):
    """Move vehicle to next station"""
    try:
        response = supabase.table("production_line").update({
            "current_station": new_station,
            "last_moved": datetime.utcnow().isoformat()
        }).eq("vehicle_id", vehicle_id).execute()
        return True
    except Exception as e:
        st.error(f"Error moving vehicle: {str(e)}")
        return False

def add_vehicle_to_line(supabase, vehicle_id, vehicle_number, initial_station="Body Shop"):
    """Add new vehicle to production line"""
    try:
        vehicle_data = {
            "vehicle_id": vehicle_id,
            "vehicle_number": vehicle_number,
            "current_station": initial_station,
            "added_at": datetime.utcnow().isoformat(),
            "last_moved": datetime.utcnow().isoformat()
        }
        response = supabase.table("production_line").insert(vehicle_data).execute()
        return response.data[0] if response.data else None
    except Exception as e:
        st.error(f"Error adding vehicle: {str(e)}")
        return None

def get_vehicles_at_station(supabase, station_name):
    """Get all vehicles at a specific station"""
    try:
        response = supabase.table("production_line").select("*").eq("current_station", station_name).execute()
        return response.data
    except:
        return []

# Production line visualization page
def production_line_page(supabase, update_activity, log_audit_event, st_session_state):
    """Main production line visualization page"""
    update_activity()
    st.header("🚌 Live Production Line Tracking")
    
    # Define production stations in order
    stations = ["Body Shop", "Paint Shop", "Assembly", "Quality Check", "Final Inspection", "Completed"]
    
    # Add new vehicle section
    with st.expander("➕ Add New Vehicle to Production Line"):
        col1, col2 = st.columns(2)
        with col1:
            new_vehicle_id = st.text_input("Vehicle ID", placeholder="V006")
            new_vehicle_number = st.text_input("Vehicle Number", placeholder="BUS-006")
        with col2:
            initial_station = st.selectbox("Starting Station", stations[:-1])  # Exclude "Completed"
            
        if st.button("Add Vehicle to Line"):
            if new_vehicle_id and new_vehicle_number:
                result = add_vehicle_to_line(supabase, new_vehicle_id, new_vehicle_number, initial_station)
                if result:
                    st.success(f"Vehicle {new_vehicle_number} added to {initial_station}!")
                    log_audit_event(st_session_state.user_id, "vehicle_added", "production_line", new_vehicle_id, f"Added vehicle {new_vehicle_number} to {initial_station}")
                    time.sleep(1)
                    st.rerun()
                else:
                    st.error("Failed to add vehicle. It might already exist.")
            else:
                st.warning("Please enter both Vehicle ID and Number")
    
    st.markdown("---")
    st.subheader("🏭 Production Line Status")
    
    # Get current production line data
    production_data = get_production_line_data(supabase)
    
    # Create columns for each station
    cols = st.columns(len(stations))
    
    for i, (col, station) in enumerate(zip(cols, stations)):
        with col:
            st.markdown(f"### {station}")
            st.image(f"https://placehold.co/200x100/003366/white?text={station.replace(' ', '+')}", use_column_width=True)
            
            # Get vehicles at this station
            vehicles_at_station = [v for v in production_data if v['current_station'] == station]
            
            if vehicles_at_station:
                for vehicle in vehicles_at_station:
                    st.markdown(f"""
                    <div style='border: 2px solid #4CAF50; border-radius: 10px; padding: 10px; margin: 5px 0; background-color: #f0fff0;'>
                        <h4 style='margin: 0; color: #2E7D32;'>🚌 {vehicle['vehicle_number']}</h4>
                        <p style='margin: 5px 0; font-size: 12px;'>ID: {vehicle['vehicle_id']}</p>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    # Show move button if not at final station
                    if station != "Completed" and st_session_state.role in ["supervisor", "admin"]:
                        next_station = stations[i + 1]
                        if st.button(f"→ {next_station}", key=f"move_{vehicle['vehicle_id']}"):
                            if update_vehicle_station(supabase, vehicle['vehicle_id'], next_station):
                                st.success(f"Moved {vehicle['vehicle_number']} to {next_station}!")
                                log_audit_event(st_session_state.user_id, "vehicle_moved", "production_line", vehicle['vehicle_id'], f"Moved {vehicle['vehicle_number']} from {station} to {next_station}")
                                time.sleep(1)
                                st.rerun()
                            else:
                                st.error("Failed to move vehicle")
            else:
                st.info("No vehicles")
                
            # Show station statistics
            st.caption(f"📊 Vehicles: {len(vehicles_at_station)}")
    
    # Add auto-refresh
    st.markdown("---")
    if st.button("🔄 Refresh View"):
        st.rerun()
    
    # Auto-refresh every 30 seconds
    st.markdown("<meta http-equiv='refresh' content='30'>", unsafe_allow_html=True)
    st.caption("🔄 Auto-refreshing every 30 seconds...")

    # Production line analytics
    with st.expander("📈 Production Line Analytics"):
        total_vehicles = len(production_data)
        completed_vehicles = len([v for v in production_data if v['current_station'] == "Completed"])
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Vehicles", total_vehicles)
        with col2:
            st.metric("Completed", completed_vehicles)
        with col3:
            st.metric("In Progress", total_vehicles - completed_vehicles)
        
        # Station occupancy chart
        station_counts = {}
        for station in stations:
            station_counts[station] = len([v for v in production_data if v['current_station'] == station])
        
        chart_data = pd.DataFrame({
            "Station": list(station_counts.keys()),
            "Vehicles": list(station_counts.values())
        })
        
        st.bar_chart(chart_data.set_index("Station"))

# SQL setup function (run this once)
def setup_production_line_table(supabase):
    """Setup the production line table (run this once)"""
    setup_sql = """
    CREATE TABLE IF NOT EXISTS production_line (
        id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
        vehicle_id VARCHAR(100) UNIQUE NOT NULL,
        vehicle_number VARCHAR(100) NOT NULL,
        current_station VARCHAR(100) NOT NULL,
        added_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        last_moved TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    );

    -- Insert sample vehicles if table is empty
    INSERT INTO production_line (vehicle_id, vehicle_number, current_station)
    SELECT 'V001', 'BUS-001', 'Body Shop'
    WHERE NOT EXISTS (SELECT 1 FROM production_line WHERE vehicle_id = 'V001');

    INSERT INTO production_line (vehicle_id, vehicle_number, current_station)
    SELECT 'V002', 'BUS-002', 'Paint Shop'
    WHERE NOT EXISTS (SELECT 1 FROM production_line WHERE vehicle_id = 'V002');

    INSERT INTO production_line (vehicle_id, vehicle_number, current_station)
    SELECT 'V003', 'BUS-003', 'Assembly'
    WHERE NOT EXISTS (SELECT 1 FROM production_line WHERE vehicle_id = 'V003');

    INSERT INTO production_line (vehicle_id, vehicle_number, current_station)
    SELECT 'V004', 'BUS-004', 'Quality Check'
    WHERE NOT EXISTS (SELECT 1 FROM production_line WHERE vehicle_id = 'V004');

    INSERT INTO production_line (vehicle_id, vehicle_number, current_station)
    SELECT 'V005', 'BUS-005', 'Final Inspection'
    WHERE NOT EXISTS (SELECT 1 FROM production_line WHERE vehicle_id = 'V005');
    """
    
    try:
        # Execute the SQL (you might need to run this manually in Supabase SQL editor)
        st.info("Please run the SQL setup in your Supabase dashboard to create the production_line table")
    except:
        st.warning("Production line table setup required")
