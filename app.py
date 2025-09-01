-- USERS TABLE
create table if not exists users (
    id uuid primary key default gen_random_uuid(),
    username text unique not null,
    password_hash text not null, -- bcrypt hash, no plain text
    role text check (role in ('operator','quality','admin','god_admin')) not null,
    created_at timestamp default now(),
    is_online boolean default false
);

-- PRODUCTION METRICS
create table if not exists production_metrics (
    id uuid primary key default gen_random_uuid(),
    user_id uuid references users(id) on delete cascade,
    shift text check (shift in ('Morning','Evening','Night')) not null,
    date date not null,
    units_produced int not null check (units_produced >= 0),
    defects int not null check (defects >= 0),
    created_at timestamp default now()
);

-- QUALITY METRICS
create table if not exists quality_metrics (
    id uuid primary key default gen_random_uuid(),
    user_id uuid references users(id) on delete cascade,
    shift text check (shift in ('Morning','Evening','Night')) not null,
    date date not null,
    defect_type text not null,
    count int not null check (count >= 0),
    created_at timestamp default now()
);

-- ACCESS REQUESTS (separated for role & password)
create table if not exists access_requests (
    id uuid primary key default gen_random_uuid(),
    user_id uuid references users(id) on delete cascade,
    request_type text check (request_type in ('role_change','password_reset')) not null,
    requested_role text check (requested_role in ('operator','quality','admin','god_admin','none')) default 'none',
    new_password_hash text, -- only used for password reset
    status text check (status in ('pending','approved','rejected')) default 'pending',
    created_at timestamp default now()
);

-- AUDIT LOGS
create table if not exists audit_logs (
    id uuid primary key default gen_random_uuid(),
    user_id uuid references users(id) on delete set null,
    action text not null,
    details jsonb,
    ip_address text,
    created_at timestamp default now()
);
