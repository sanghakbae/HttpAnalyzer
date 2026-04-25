create table if not exists public.capture_har_analyses (
  id bigint generated always as identity primary key,
  created_at timestamptz not null default now(),
  file_name text not null,
  file_size bigint not null,
  total_entries integer not null default 0,
  average_wait_ms numeric not null default 0,
  slowest_url text,
  methods jsonb not null default '{}'::jsonb,
  top_hosts jsonb not null default '[]'::jsonb,
  status_codes jsonb not null default '{}'::jsonb,
  content_types jsonb not null default '[]'::jsonb,
  failed_requests jsonb not null default '[]'::jsonb
);

create table if not exists public.capture_http_events (
  id bigint generated always as identity primary key,
  created_at timestamptz not null default now(),
  capture_session_id uuid,
  target_url text,
  request_timestamp timestamptz,
  request_method text,
  request_url text,
  request_resource_type text,
  request_headers jsonb not null default '{}'::jsonb,
  request_body text not null default '',
  response_timestamp timestamptz,
  response_url text,
  response_status integer,
  response_status_text text,
  response_headers jsonb not null default '{}'::jsonb,
  response_body_preview text not null default '',
  error_text text
);

create table if not exists public.capture_inspection_runs (
  id bigint generated always as identity primary key,
  created_at timestamptz not null default now(),
  capture_session_id uuid,
  target_url text not null,
  started_at timestamptz,
  ended_at timestamptz not null default now(),
  total_exchanges integer not null default 0,
  total_errors integer not null default 0,
  total_findings integer not null default 0,
  critical_findings integer not null default 0,
  high_findings integer not null default 0,
  security_only boolean not null default false,
  mask_sensitive boolean not null default true,
  excluded_patterns jsonb not null default '[]'::jsonb,
  owasp_summary jsonb not null default '[]'::jsonb,
  endpoint_summary jsonb not null default '[]'::jsonb,
  report_snapshot jsonb not null default '{}'::jsonb
);

create unique index if not exists capture_inspection_runs_session_id_uidx
  on public.capture_inspection_runs (capture_session_id)
  where capture_session_id is not null;

create index if not exists capture_inspection_runs_created_at_idx
  on public.capture_inspection_runs (created_at desc);

create index if not exists capture_inspection_runs_target_url_idx
  on public.capture_inspection_runs (target_url, ended_at desc);

create index if not exists capture_http_events_created_at_idx
  on public.capture_http_events (created_at desc);

create index if not exists capture_http_events_session_idx
  on public.capture_http_events (capture_session_id, created_at desc);

create index if not exists capture_har_analyses_created_at_idx
  on public.capture_har_analyses (created_at desc);

grant usage on schema public to service_role;
grant all privileges on table public.capture_har_analyses to service_role;
grant all privileges on table public.capture_http_events to service_role;
grant all privileges on table public.capture_inspection_runs to service_role;
grant usage, select on all sequences in schema public to service_role;
