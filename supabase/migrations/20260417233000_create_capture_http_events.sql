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
