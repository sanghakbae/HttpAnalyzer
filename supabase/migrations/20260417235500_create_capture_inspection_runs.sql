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
