# MMCL Production Ultimate Database
🏭 Manufacturing Production Management System

A comprehensive Streamlit-based production management system for automotive manufacturing, featuring real-time production line tracking, OEE calculations, quality management, and role-based access control.

![version](https://img.shields.io/badge/version-1.0.0-blue)
![python](https://img.shields.io/badge/python-3.8+-green)
![streamlit](https://img.shields.io/badge/streamlit-1.28+-red)
![supabase](https://img.shields.io/badge/supabase-postgresql-green)

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Technology Stack](#technology-stack)
- [Installation](#installation)
- [Configuration](#configuration)
- [Database Schema](#database-schema)
- [User Roles & Permissions](#user-roles--permissions)
- [Key Features](#key-features)
- [Security Features](#security-features)
- [API Reference](#api-reference)
- [Contributing](#contributing)
- [License](#license)

## Overview

The MMCL Production Ultimate Database is an enterprise-grade production management system designed for automotive manufacturing environments. It provides real-time visibility into production lines, comprehensive OEE (Overall Equipment Effectiveness) tracking, quality management, and robust access control.

### Key Benefits

- 📊 Real-time production monitoring
- 🔒 Role-based security with approval workflows
- 📈 Advanced OEE and manufacturing metrics
- 🚌 Live production line visualizer
- 📱 Mobile-responsive design
- 🔐 Audit logging for compliance

## Features

### Core Functionality

#### User Authentication & Authorization

- Secure login with bcrypt password hashing
- Role-based access control (Viewer, Supervisor, Admin)
- Account approval workflow
- Password change requests with admin approval
- Automatic logout after inactivity

#### Production Dashboard

- Real-time OEE calculations (Availability, Performance, Quality)
- Interactive charts and visualizations
- Date range filtering (Today, Week, Month, Custom)
- Department filtering
- Export functionality (CSV reports)

#### Live Production Line Visualizer

- Real-time vehicle tracking across production lines
- Visual representation of Trim Line, Chassis Line, Weld Shop, Paint Shop, PDI
- Drag-and-drop style vehicle movement
- Completion tracking

#### Data Entry Forms

- Production metrics entry
- Quality control data entry
- Shift-based reporting
- Downtime tracking with reasons

#### Admin Controls

- User management (create, edit, delete)
- Access request approvals
- Password reset functionality
- Force logout capability
- Audit log viewing

### Advanced Metrics

- OEE (Overall Equipment Effectiveness)
- Takt Time
- Cycle Time
- First Pass Yield (FPY)
- Scrap Rate
- Rework Rate
- Capacity Utilization
- On-Time Delivery
- Cost of Poor Quality

## Technology Stack

### Frontend

- **Streamlit** - Web application framework
- **Plotly** - Interactive charts and visualizations
- **Pandas** - Data manipulation and analysis

### Backend

- **Supabase** - PostgreSQL database with real-time capabilities
- **bcrypt** - Password hashing and verification

### Infrastructure

- **Python 3.8+** - Core programming language
- **Streamlit Cloud** - Deployment platform
- **Supabase Cloud** - Database hosting

## Installation

### Prerequisites

- Python 3.8 or higher
- Supabase account
- Git (optional)

### Local Development Setup

#### 1. Clone the repository

```bash
git clone https://github.com/yourusername/mmcl-production-database.git
cd mmcl-production-database
```

#### 2. Create virtual environment

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

#### 3. Install dependencies

```bash
pip install -r requirements.txt
```

#### 4. Configure Supabase

Create a `.streamlit/secrets.toml` file:

```toml
SUPABASE_URL = "your-supabase-url"
SUPABASE_KEY = "your-supabase-anon-key"
GOD_ADMIN_PASSWORD = "your-secure-admin-password"
```

#### 5. Run the application

```bash
streamlit run app.py
```

## Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| SUPABASE_URL | Supabase project URL | Yes |
| SUPABASE_KEY | Supabase anonymous key | Yes |
| GOD_ADMIN_PASSWORD | Default admin password | Yes |

### Supabase Setup

1. Create a new Supabase project

2. Run the following SQL to create tables:

```sql
-- Users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'viewer',
    approved BOOLEAN DEFAULT FALSE,
    department TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    is_online BOOLEAN DEFAULT FALSE,
    last_activity TIMESTAMP
);

-- Production metrics table
CREATE TABLE production_metrics (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT NOW(),
    date DATE NOT NULL,
    shift TEXT,
    manpower_available INTEGER,
    manpower_required INTEGER,
    production_plan INTEGER,
    production_actual INTEGER,
    scrap INTEGER,
    rework_units INTEGER DEFAULT 0,
    cycle_time_minutes FLOAT,
    downtime_hours FLOAT,
    scheduled_downtime_hours FLOAT,
    order_quantity INTEGER,
    completed_quantity INTEGER,
    good_units INTEGER,
    downtime_reason TEXT,
    planned_hours FLOAT DEFAULT 8,
    labor_cost_per_hour FLOAT DEFAULT 25,
    material_cost_per_unit FLOAT DEFAULT 100,
    notes TEXT,
    entered_by TEXT,
    department TEXT,
    availability FLOAT,
    performance FLOAT,
    quality FLOAT,
    oee FLOAT
);

-- Quality metrics table
CREATE TABLE quality_metrics (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT NOW(),
    date DATE NOT NULL,
    shift TEXT,
    total_vehicles INTEGER,
    passed_vehicles INTEGER,
    failed_vehicles INTEGER,
    total_defects INTEGER,
    critical_defects INTEGER,
    major_defects INTEGER,
    minor_defects INTEGER,
    dpu FLOAT,
    fpy FLOAT,
    defect_types TEXT,
    corrective_actions TEXT,
    entered_by TEXT,
    department TEXT
);

-- Production line tracking
CREATE TABLE production_line (
    id SERIAL PRIMARY KEY,
    vehicle_number TEXT NOT NULL,
    line_name TEXT NOT NULL,
    station_name TEXT NOT NULL,
    status TEXT DEFAULT 'in_progress',
    entered_by TEXT,
    timestamp TIMESTAMP DEFAULT NOW(),
    previous_station TEXT,
    next_station TEXT
);

-- Access requests table
CREATE TABLE access_requests (
    id SERIAL PRIMARY KEY,
    username TEXT NOT NULL,
    requested_role TEXT,
    new_password_hash TEXT,
    reason TEXT,
    status TEXT DEFAULT 'pending',
    requested_at TIMESTAMP DEFAULT NOW(),
    reviewed_at TIMESTAMP,
    approved_by TEXT,
    request_type TEXT DEFAULT 'role_access'
);

-- Audit log table
CREATE TABLE audit_log (
    id SERIAL PRIMARY KEY,
    user_id INTEGER,
    username TEXT,
    action TEXT,
    target_type TEXT,
    target_id TEXT,
    details TEXT,
    timestamp TIMESTAMP DEFAULT NOW(),
    ip_address TEXT
);
```

## Database Schema

### Table Relationships

```
users
  ├── id (PK)
  ├── username
  ├── password_hash
  ├── role
  ├── approved
  └── department

production_metrics
  ├── id (PK)
  ├── date
  ├���─ department (FK to users.department)
  ├── entered_by (FK to users.username)
  └── ...

quality_metrics
  ├── id (PK)
  ├── date
  ├── entered_by (FK to users.username)
  └── ...

production_line
  ├── id (PK)
  ├── vehicle_number
  ├── line_name
  ├── station_name
  ├── status
  └── entered_by (FK to users.username)

access_requests
  ├── id (PK)
  ├── username (FK to users.username)
  ├── status
  └── request_type

audit_log
  ├── id (PK)
  ├── user_id (FK to users.id)
  ├── username
  └── ...
```

## User Roles & Permissions

### 👁️ Viewer

- View dashboard and reports
- Request elevated access
- View own profile
- Request password changes

### 👷 Supervisor

- All Viewer permissions
- Enter production data (department-specific)
- Enter quality data (if in QAHSE)
- View production line visualizer

### 👑 Admin

- All permissions
- User management (approve/reject)
- Access request management
- Password resets for users
- Force logout users
- View audit logs
- Edit/delete any records
- System monitoring

## Key Features

### OEE Calculation

The system calculates OEE using the standard formula:

```
OEE = Availability × Performance × Quality

Availability = (Planned Production Time - Downtime) / Planned Production Time
Performance = (Total Units / Ideal Production Rate) / Planned Production Time
Quality = Good Units / Total Units
```

### Production Line Visualization

- Real-time vehicle tracking across production lines
- Visual representation with bus icons
- Move vehicles between stations with one click
- Complete vehicles when they reach final station

## Security Features

- **Password Hashing**: bcrypt with salt
- **Auto Logout**: 30 minutes of inactivity
- **Session Management**: Per-user session tracking
- **Approval Workflow**: New accounts require admin approval
- **Audit Logging**: All actions logged for compliance
- **Role-Based Access**: Granular permissions per role

## API Reference

### Core Functions

#### Authentication

```python
# User management
get_user(username)
create_user(username, password, role, approved, department)
check_password(password, hashed)
hash_password(password)

# Session management
set_user_online_status(user_id, is_online)
auto_logout_check()
update_activity()
```

#### Production Metrics

```python
# OEE calculations
calculate_oee(record)
calculate_daily_oee(records)
calculate_manufacturing_metrics(records)

# Data retrieval
get_production_metrics(start_date, end_date, department)
get_quality_metrics(start_date, end_date, department)
```

#### Production Line

```python
# Vehicle tracking
get_production_lines()
get_vehicles_in_production()
add_vehicle_to_line(vehicle_number, line_name, station_name, entered_by)
move_vehicle(vehicle_id, new_station, new_line)
complete_vehicle(vehicle_id)
```

## Contributing

We welcome contributions! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Development Guidelines

- Follow PEP 8 style guide
- Add docstrings for new functions
- Update README for significant changes
- Test thoroughly before submitting

## Troubleshooting

### Common Issues

#### Login Issues

- Verify credentials
- Check if account is approved
- Ensure Supabase connection is working

#### Data Not Saving

- Check Supabase RLS policies
- Verify user has correct permissions
- Check network connectivity

#### Production Line Not Updating

- Refresh the page
- Check browser console for errors
- Verify WebSocket connection

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, email support@mmcl.com or create an issue in the GitHub repository.

---

Built with ❤️ for MMCL Manufacturing
