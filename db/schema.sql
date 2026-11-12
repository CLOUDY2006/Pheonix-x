-- PHOENIX X — Supabase / PostgreSQL schema
-- Run in the Supabase SQL editor. The demo runs fully without it (in-memory store); with SUPABASE_URL +
-- SUPABASE_SERVICE_ROLE_KEY set, the server mirrors events / incidents / audit entries into the three
-- "mirror" tables at the bottom (jsonb payload). The normalised tables above them are the production design.
create extension if not exists "pgcrypto";

create table organizations (id uuid primary key default gen_random_uuid(), name text not null, created_at timestamptz default now());
create table roles (id serial primary key, name text unique not null check (name in ('viewer','analyst','admin')), description text);
insert into roles(name, description) values ('viewer','read-only'),('analyst','investigate, launch scenarios, notes'),('admin','approve/reject response actions, settings');
create table users (id uuid primary key references auth.users(id) on delete cascade, org_id uuid references organizations(id), email text unique not null, display_name text, role_id int references roles(id), status text default 'active' check (status in ('active','suspended')), created_at timestamptz default now());
create table assets (id uuid primary key default gen_random_uuid(), org_id uuid references organizations(id), kind text check (kind in ('user','host','server','resource','cloud_role','bucket')), name text not null, environment text default 'sandbox' check (environment in ('sandbox','production')), criticality text default 'low' check (criticality in ('low','medium','high','critical')), isolated boolean default false, attributes jsonb default '{}', unique(org_id, kind, name));
create table security_events (id text primary key, org_id uuid references organizations(id), ts timestamptz not null, source text not null check (source in ('authentication','application','system','network','api','file','cloud')), type text not null, origin text not null check (origin in ('generated','scenario','ingested')), actor text, ip inet, host text, resource text, outcome text, details jsonb default '{}');
create index on security_events (ts desc); create index on security_events (actor, ts); create index on security_events (ip, ts); create index on security_events (origin);
create table threat_indicators (id uuid primary key default gen_random_uuid(), type text check (type in ('ip','domain','hash')), value text not null, verdict text check (verdict in ('malicious','suspicious','no_detections','unknown')), source text, tags text[], queried_at timestamptz default now(), unique(type, value));
create table incidents (id text primary key, org_id uuid references organizations(id), title text, state text, status text, priority text check (priority in ('P1','P2','P3','P4')), severity text, risk_score int check (risk_score between 0 and 100), analyst uuid references users(id), disposition text, created_at timestamptz default now(), resolved_at timestamptz, report_md text);
create index on incidents (state, priority);
create table incident_evidence (id uuid primary key default gen_random_uuid(), incident_id text references incidents(id) on delete cascade, event_id text references security_events(id), sha256 text, preserved_at timestamptz default now());
create table agent_executions (id uuid primary key default gen_random_uuid(), incident_id text references incidents(id), agent text, label text, status text, started_at timestamptz, ended_at timestamptz, error text);
create table agent_messages (id uuid primary key default gen_random_uuid(), incident_id text references incidents(id), from_agent text, to_agent text, type text, payload jsonb, ts timestamptz default now());
create table response_actions (id text primary key, incident_id text references incidents(id), type text not null, target jsonb, tier text check (tier in ('automatic','approval','restricted')), status text, reason text, result jsonb, executed_at timestamptz);
create table action_approvals (id uuid primary key default gen_random_uuid(), action_id text references response_actions(id), decision text check (decision in ('approved','rejected')), decided_by uuid references users(id), comment text, decided_at timestamptz default now());
create table recovery_tasks (id text primary key, incident_id text references incidents(id), title text, kind text, owner text, status text, depends_on text[], completed_at timestamptz);
create table backup_records (id text primary key, asset_id uuid references assets(id), taken_at timestamptz, verified boolean, immutable boolean, size_gb numeric);
create table notifications (id text primary key, incident_id text references incidents(id), channel text, status text check (status in ('delivered','simulated','failed')), confirmation text, ts timestamptz default now());
create table audit_logs (seq bigserial primary key, ts timestamptz default now(), actor text, action text, incident_id text, detail jsonb, prev_hash text, hash text not null);
create table security_policies (id text primary key, title text, body text);
create table integration_configs (name text primary key, status text, config jsonb default '{}', updated_at timestamptz default now()); -- never store secrets here; use env vars / Vault

-- Row-level security: viewers read; analysts write notes/tasks; only admins decide approvals; audit is append-only.
alter table incidents enable row level security; alter table security_events enable row level security; alter table response_actions enable row level security;
alter table action_approvals enable row level security; alter table audit_logs enable row level security; alter table recovery_tasks enable row level security;
create or replace function app_role() returns text language sql stable as $$ select r.name from users u join roles r on r.id=u.role_id where u.id = auth.uid() $$;
create policy read_all_incidents on incidents for select using (app_role() in ('viewer','analyst','admin'));
create policy analyst_update_incidents on incidents for update using (app_role() in ('analyst','admin'));
create policy read_events on security_events for select using (app_role() is not null);
create policy read_actions on response_actions for select using (app_role() is not null);
create policy admin_approve on action_approvals for insert with check (app_role() = 'admin');
create policy read_approvals on action_approvals for select using (app_role() is not null);
create policy read_audit on audit_logs for select using (app_role() is not null);
create policy analyst_tasks on recovery_tasks for update using (app_role() in ('analyst','admin'));
-- audit_logs: no update/delete policy => append-only for every non-service role.

-- Mirror tables used by the demo server's write-through (service-role key bypasses RLS)
create table mirror_security_events (id text primary key, data jsonb, updated_at timestamptz);
create table mirror_incidents (id text primary key, data jsonb, updated_at timestamptz);
create table mirror_audit_logs (id text primary key, data jsonb, updated_at timestamptz);
-- Realtime: alter publication supabase_realtime add table mirror_incidents, mirror_security_events;
