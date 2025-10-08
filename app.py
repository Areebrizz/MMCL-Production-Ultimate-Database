# -------------------------
# Enhanced Dashboard Page with Modern UI
# -------------------------
def dashboard_page():
    update_activity()
    
    # Enhanced CSS for modern dashboard
    st.markdown("""
    <style>
    .main-header {
        font-size: 2.5rem;
        font-weight: 700;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
        padding: 1.5rem;
        border-radius: 15px;
        border: 1px solid #e1e8ed;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        transition: transform 0.2s ease;
    }
    .metric-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 12px rgba(0, 0, 0, 0.15);
    }
    .metric-value {
        font-size: 2rem;
        font-weight: 700;
        color: #2c3e50;
        margin: 0.5rem 0;
    }
    .metric-label {
        font-size: 0.9rem;
        color: #7f8c8d;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    .progress-bar-container {
        background: #ecf0f1;
        border-radius: 10px;
        height: 8px;
        margin: 10px 0;
        overflow: hidden;
    }
    .progress-bar {
        height: 100%;
        border-radius: 10px;
        transition: width 0.3s ease;
    }
    .kpi-badge {
        display: inline-block;
        padding: 0.25rem 0.75rem;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 600;
        margin-left: 0.5rem;
    }
    .badge-excellent { background: #2ecc71; color: white; }
    .badge-good { background: #3498db; color: white; }
    .badge-warning { background: #f39c12; color: white; }
    .badge-poor { background: #e74c3c; color: white; }
    .section-header {
        font-size: 1.5rem;
        font-weight: 600;
        color: #2c3e50;
        margin: 2rem 0 1rem 0;
        padding-bottom: 0.5rem;
        border-bottom: 2px solid #3498db;
    }
    </style>
    """, unsafe_allow_html=True)
    
    st.markdown('<div class="main-header">🏭 Manufacturing Performance Dashboard</div>', unsafe_allow_html=True)
    
    # Date range and filter controls
    col1, col2, col3, col4 = st.columns([2, 2, 2, 1])
    
    with col1:
        date_range = st.selectbox(
            "📅 Date Range", 
            ["Today", "This Week", "This Month", "Last Week", "Last Month", "Custom Range"],
            key="date_range_select"
        )
    
    with col2:
        if date_range == "Custom Range":
            start_date = st.date_input("Start Date", value=date.today() - timedelta(days=7))
            end_date = st.date_input("End Date", value=date.today())
        else:
            today = date.today()
            if date_range == "Today":
                start_date = today
                end_date = today
            elif date_range == "This Week":
                start_date = today - timedelta(days=today.weekday())
                end_date = start_date + timedelta(days=6)
            elif date_range == "Last Week":
                start_date = today - timedelta(days=today.weekday() + 7)
                end_date = start_date + timedelta(days=6)
            elif date_range == "This Month":
                start_date = today.replace(day=1)
                next_month = today.replace(day=28) + timedelta(days=4)
                end_date = next_month - timedelta(days=next_month.day)
            else:  # Last Month
                first_day_this_month = today.replace(day=1)
                end_date = first_day_this_month - timedelta(days=1)
                start_date = end_date.replace(day=1)
    
    with col3:
        departments = ["All"] + list(pd.DataFrame(get_all_users())["department"].dropna().unique())
        department_filter = st.selectbox("🏭 Filter Department", departments, key="dept_filter")
    
    with col4:
        st.markdown("##")
        if st.button("🔄 Refresh", use_container_width=True):
            st.rerun()
    
    # Fetch and calculate data
    records = get_production_metrics(start_date, end_date, department_filter)
    
    # Debug information
    st.write(f"**Debug Info:** Found {len(records)} records for {department_filter} from {start_date} to {end_date}")
    
    if not records:
        st.warning("No production records found for the selected criteria.")
        st.info("Try selecting a different date range or department, or check if data has been entered.")
        return
    
    # Helper functions defined INSIDE dashboard_page
    def get_performance_badge(value, metric_type="positive"):
        """Return performance badge based on value"""
        # Ensure value is numeric for comparison
        try:
            numeric_value = float(value)
        except (ValueError, TypeError):
            return "N/A", "badge-warning"
        
        if metric_type == "positive":  # Higher is better
            if numeric_value >= 85: 
                return "Excellent", "badge-excellent"
            elif numeric_value >= 70: 
                return "Good", "badge-good"
            elif numeric_value >= 50: 
                return "Fair", "badge-warning"
            else: 
                return "Poor", "badge-poor"
        else:  # Lower is better
            if numeric_value <= 5: 
                return "Excellent", "badge-excellent"
            elif numeric_value <= 15: 
                return "Good", "badge-good"
            elif numeric_value <= 25: 
                return "Fair", "badge-warning"
            else: 
                return "Poor", "badge-poor"

    def render_enhanced_metric(title, value, unit="%", progress_value=0, metric_type="positive", help_text=""):
        """Render enhanced metric card with performance badge"""
        badge_text, badge_class = get_performance_badge(value, metric_type)
        
        # Ensure progress_value is numeric and within bounds
        try:
            safe_progress = max(0, min(1, float(progress_value)))
        except (ValueError, TypeError):
            safe_progress = 0
        
        progress_color = "#2ecc71"  # Green
        try:
            numeric_value = float(value)
            if metric_type == "positive":
                if numeric_value < 50: progress_color = "#e74c3c"
                elif numeric_value < 70: progress_color = "#f39c12"
                elif numeric_value < 85: progress_color = "#3498db"
            else:
                if numeric_value > 25: progress_color = "#e74c3c"
                elif numeric_value > 15: progress_color = "#f39c12"
                elif numeric_value > 5: progress_color = "#3498db"
        except (ValueError, TypeError):
            progress_color = "#bdc3c7"  # Gray for invalid values
        
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">{title}</div>
            <div style="display: flex; align-items: center; justify-content: space-between;">
                <div class="metric-value">{value}{unit}</div>
                <span class="kpi-badge {badge_class}">{badge_text}</span>
            </div>
            <div class="progress-bar-container">
                <div class="progress-bar" style="width: {safe_progress*100}%; background: {progress_color};"></div>
            </div>
            <div style="font-size: 0.8rem; color: #7f8c8d;">{help_text}</div>
        </div>
        """, unsafe_allow_html=True)

    # Calculate metrics after helper functions are defined
    metrics = calculate_manufacturing_metrics(records)
    df = pd.DataFrame(records)
    df["date"] = pd.to_datetime(df["date"], errors="coerce")
    
    # Main KPI Section - OEE and Core Metrics
    st.markdown('<div class="section-header">📊 Overall Equipment Effectiveness (OEE)</div>', unsafe_allow_html=True)
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        render_enhanced_metric(
            "Overall OEE", 
            f"{metrics['oee']['oee']:.1f}", 
            progress_value=metrics['oee']['oee']/100,
            help_text="World-class: 85%+"
        )
    
    with col2:
        render_enhanced_metric(
            "Availability", 
            f"{metrics['oee']['availability']:.1f}", 
            progress_value=metrics['oee']['availability']/100,
            help_text="Production time vs Planned"
        )
    
    with col3:
        render_enhanced_metric(
            "Performance", 
            f"{metrics['oee']['performance']:.1f}", 
            progress_value=metrics['oee']['performance']/100,
            help_text="Actual vs Planned output"
        )
    
    with col4:
        render_enhanced_metric(
            "Quality", 
            f"{metrics['oee']['quality']:.1f}", 
            progress_value=metrics['oee']['quality']/100,
            help_text="Good units vs Total units"
        )
    
    # Quality Metrics Section
    st.markdown('<div class="section-header">🎯 Quality Performance</div>', unsafe_allow_html=True)
    
    col5, col6, col7, col8 = st.columns(4)
    
    with col5:
        render_enhanced_metric(
            "First Pass Yield", 
            f"{metrics['first_pass_yield']:.1f}", 
            progress_value=metrics['first_pass_yield']/100,
            help_text="Units passing first inspection"
        )
    
    with col6:
        render_enhanced_metric(
            "Scrap Rate", 
            f"{metrics['scrap_rate']:.1f}", 
            progress_value=1-(metrics['scrap_rate']/100),
            metric_type="negative",
            help_text="Lower is better"
        )
    
    with col7:
        render_enhanced_metric(
            "Rework Rate", 
            f"{metrics['rework_rate']:.1f}", 
            progress_value=1-(metrics['rework_rate']/100),
            metric_type="negative",
            help_text="Lower is better"
        )
    
    with col8:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Cost of Poor Quality</div>
            <div class="metric-value">${metrics['cost_of_poor_quality']:,.0f}</div>
            <div style="font-size: 0.8rem; color: #7f8c8d;">Financial impact of quality issues</div>
        </div>
        """, unsafe_allow_html=True)
    
    # Efficiency Metrics Section
    st.markdown('<div class="section-header">⚡ Efficiency Metrics</div>', unsafe_allow_html=True)
    
    col9, col10, col11, col12 = st.columns(4)
    
    with col9:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Takt Time</div>
            <div class="metric-value">{metrics['takt_time']:.1f} min</div>
            <div style="font-size: 0.8rem; color: #7f8c8d;">Customer demand rate</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col10:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Cycle Time</div>
            <div class="metric-value">{metrics['avg_cycle_time']:.1f} min</div>
            <div style="font-size: 0.8rem; color: #7f8c8d;">Average per unit</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col11:
        render_enhanced_metric(
            "Capacity Utilization", 
            f"{metrics['capacity_utilization']:.1f}", 
            progress_value=metrics['capacity_utilization']/100,
            help_text="Optimal: 85-90%"
        )
    
    with col12:
        render_enhanced_metric(
            "On-Time Delivery", 
            f"{metrics['on_time_delivery']:.1f}", 
            progress_value=metrics['on_time_delivery']/100,
            help_text="Completed vs Ordered"
        )
    
    # Interactive Visualizations
    st.markdown('<div class="section-header">📈 Performance Analytics</div>', unsafe_allow_html=True)
    
    # Create tabs for different visualizations
    viz_tab1, viz_tab2, viz_tab3 = st.tabs(["OEE Trend Analysis", "Production Volume", "Quality Trends"])
    
    with viz_tab1:
        # OEE Trend with Plotly
        daily_data = []
        for day in pd.date_range(start_date, end_date):
            day_records = [r for r in records if pd.to_datetime(r['date']).date() == day.date()]
            if day_records:
                daily_oee = calculate_daily_oee(day_records)
                daily_data.append({
                    'date': day.date(),
                    'oee': daily_oee['oee'],
                    'availability': daily_oee['availability'],
                    'performance': daily_oee['performance'],
                    'quality': daily_oee['quality']
                })
        
        if daily_data:
            trend_df = pd.DataFrame(daily_data)
            
            fig = go.Figure()
            fig.add_trace(go.Scatter(x=trend_df['date'], y=trend_df['availability'], 
                                   mode='lines+markers', name='Availability', line=dict(color='#3498db', width=3)))
            fig.add_trace(go.Scatter(x=trend_df['date'], y=trend_df['performance'], 
                                   mode='lines+markers', name='Performance', line=dict(color='#2ecc71', width=3)))
            fig.add_trace(go.Scatter(x=trend_df['date'], y=trend_df['quality'], 
                                   mode='lines+markers', name='Quality', line=dict(color='#e74c3c', width=3)))
            fig.add_trace(go.Scatter(x=trend_df['date'], y=trend_df['oee'], 
                                   mode='lines+markers', name='OEE', line=dict(color='#9b59b6', width=4, dash='dash')))
            
            fig.update_layout(
                title="OEE Components Trend",
                xaxis_title="Date",
                yaxis_title="Percentage (%)",
                hovermode='x unified',
                height=400,
                template="plotly_white"
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No daily data available for trend analysis")
    
    with viz_tab2:
        # Production Volume with Plotly
        if not df.empty:
            production_data = df.groupby('date').agg({
                'production_plan': 'sum',
                'production_actual': 'sum',
                'good_units': 'sum'
            }).reset_index()
            
            fig = go.Figure()
            fig.add_trace(go.Bar(x=production_data['date'], y=production_data['production_plan'], 
                               name='Planned', marker_color='#bdc3c7', opacity=0.7))
            fig.add_trace(go.Bar(x=production_data['date'], y=production_data['production_actual'], 
                               name='Actual', marker_color='#3498db'))
            fig.add_trace(go.Scatter(x=production_data['date'], y=production_data['good_units'], 
                                   mode='lines+markers', name='Good Units', line=dict(color='#2ecc71', width=3)))
            
            fig.update_layout(
                title="Production Volume Analysis",
                xaxis_title="Date",
                yaxis_title="Units",
                barmode='group',
                height=400,
                template="plotly_white"
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No production data available")
    
    with viz_tab3:
        # Quality Trends with Plotly
        if not df.empty:
            quality_data = df.groupby('date').agg({
                'scrap': 'sum',
                'rework_units': 'sum',
                'production_actual': 'sum'
            }).reset_index()
            quality_data['scrap_rate'] = (quality_data['scrap'] / quality_data['production_actual']) * 100
            quality_data['rework_rate'] = (quality_data['rework_units'] / quality_data['production_actual']) * 100
            
            fig = make_subplots(specs=[[{"secondary_y": True}]])
            
            fig.add_trace(go.Bar(x=quality_data['date'], y=quality_data['scrap'], 
                               name='Scrap Units', marker_color='#e74c3c'), secondary_y=False)
            fig.add_trace(go.Bar(x=quality_data['date'], y=quality_data['rework_units'], 
                               name='Rework Units', marker_color='#f39c12'), secondary_y=False)
            fig.add_trace(go.Scatter(x=quality_data['date'], y=quality_data['scrap_rate'], 
                                   mode='lines+markers', name='Scrap Rate %', 
                                   line=dict(color='#c0392b', width=3)), secondary_y=True)
            
            fig.update_layout(
                title="Quality Performance Trends",
                xaxis_title="Date",
                height=400,
                template="plotly_white"
            )
            fig.update_yaxes(title_text="Units", secondary_y=False)
            fig.update_yaxes(title_text="Percentage (%)", secondary_y=True)
            
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No quality data available")
    
    # Summary Statistics Section
    st.markdown('<div class="section-header">📋 Performance Summary</div>', unsafe_allow_html=True)
    
    summary_col1, summary_col2, summary_col3, summary_col4 = st.columns(4)
    
    with summary_col1:
        st.metric("Total Units Produced", f"{metrics['total_units']:,}")
        st.metric("Good Units", f"{metrics['good_units']:,}")
    
    with summary_col2:
        st.metric("Scrap Units", f"{metrics['scrap_units']:,}")
        st.metric("Rework Units", f"{metrics['rework_units']:,}")
    
    with summary_col3:
        total_downtime = sum(record.get('downtime_hours', 0) for record in records)
        total_shifts = len(records)
        st.metric("Total Downtime Hours", f"{total_downtime:.1f}")
        st.metric("Number of Shifts", f"{total_shifts}")
    
    with summary_col4:
        avg_cycle = df['cycle_time_minutes'].mean() if 'cycle_time_minutes' in df.columns else 0
        avg_downtime = df['downtime_hours'].mean() if 'downtime_hours' in df.columns else 0
        st.metric("Avg Cycle Time", f"{avg_cycle:.1f} min")
        st.metric("Avg Downtime", f"{avg_downtime:.1f} hrs")
    
    # Quick Actions and Export
    st.markdown("---")
    action_col1, action_col2, action_col3 = st.columns(3)
    
    with action_col1:
        if st.button("📥 Export Detailed Report", use_container_width=True):
            csv = df.to_csv(index=False)
            st.download_button(
                label="Download CSV Report",
                data=csv,
                file_name=f"production_report_{start_date}_{end_date}.csv",
                mime="text/csv",
                use_container_width=True
            )
    
    with action_col2:
        if st.button("📊 Generate Performance PDF", use_container_width=True):
            st.info("PDF generation feature coming soon!")
    
    with action_col3:
        if st.button("🔄 Real-time Refresh", use_container_width=True):
            st.rerun()
