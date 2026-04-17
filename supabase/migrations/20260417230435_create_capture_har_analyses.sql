create table if not exists public.capture_har_analyses (
  id bigint generated always as identity primary key,
  created_at timestamptz not null default now(),
  file_name text not null,
  file_size bigint not null,
  total_entries integer not null,
  average_wait_ms numeric not null,
  slowest_url text,
  methods jsonb not null,
  top_hosts jsonb not null,
  status_codes jsonb not null default '{}'::jsonb,
  content_types jsonb not null default '[]'::jsonb,
  failed_requests jsonb not null default '[]'::jsonb
);
