create extension if not exists pgcrypto;

create table if not exists public.guest_sessions (
  id uuid primary key default gen_random_uuid(),
  token_hash text not null unique,
  scan_limit smallint not null default 2 check (scan_limit > 0),
  committed_scans smallint not null default 0 check (committed_scans >= 0),
  expires_at timestamptz not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.guest_scan_reservations (
  id uuid primary key,
  guest_session_id uuid not null references public.guest_sessions(id) on delete cascade,
  request_id uuid not null,
  payload_hash text not null,
  status text not null check (status in ('reserved', 'processing', 'committed', 'rolled_back', 'expired')),
  result_json jsonb,
  error_code text,
  lease_expires_at timestamptz,
  retention_expires_at timestamptz not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (guest_session_id, request_id)
);

create table if not exists public.scans (
  id uuid primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  request_id uuid not null,
  payload_hash text,
  input_type text not null,
  original_input text not null,
  verdict text not null,
  risk_score numeric(6,3) not null check (risk_score between 0 and 100),
  response_json jsonb not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (user_id, request_id)
);

alter table public.scans
  add column if not exists payload_hash text;

update public.scans
set payload_hash = encode(
  digest(
    convert_to(input_type, 'UTF8') ||
      decode('00', 'hex') ||
      convert_to(original_input, 'UTF8'),
    'sha256'
  ),
  'hex'
)
where payload_hash is null;

alter table public.scans
  alter column payload_hash set not null;

create table if not exists public.scan_urls (
  id uuid primary key default gen_random_uuid(),
  scan_id uuid not null references public.scans(id) on delete cascade,
  position smallint not null,
  original_url text not null,
  normalized_url text,
  verdict text not null,
  risk_score numeric(6,3) not null check (risk_score between 0 and 100),
  result_json jsonb not null,
  created_at timestamptz not null default now(),
  unique (scan_id, position)
);

create index if not exists scans_user_created_idx on public.scans(user_id, created_at desc);
create index if not exists scan_urls_scan_position_idx on public.scan_urls(scan_id, position);
create index if not exists guest_sessions_expires_idx on public.guest_sessions(expires_at);
create index if not exists guest_reservations_retention_idx on public.guest_scan_reservations(retention_expires_at);

alter table public.guest_sessions enable row level security;
alter table public.guest_scan_reservations enable row level security;
alter table public.scans enable row level security;
alter table public.scan_urls enable row level security;

create policy guest_sessions_deny_client on public.guest_sessions for all to anon, authenticated using (false) with check (false);
create policy guest_reservations_deny_client on public.guest_scan_reservations for all to anon, authenticated using (false) with check (false);

create policy scans_select_own on public.scans for select to authenticated using (user_id = auth.uid());
create policy scans_insert_own on public.scans for insert to authenticated with check (user_id = auth.uid());
create policy scans_update_own on public.scans for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
create policy scans_delete_own on public.scans for delete to authenticated using (user_id = auth.uid());

create policy scan_urls_select_own on public.scan_urls for select to authenticated using (exists (select 1 from public.scans s where s.id = scan_id and s.user_id = auth.uid()));
create policy scan_urls_insert_own on public.scan_urls for insert to authenticated with check (exists (select 1 from public.scans s where s.id = scan_id and s.user_id = auth.uid()));
create policy scan_urls_update_own on public.scan_urls for update to authenticated using (exists (select 1 from public.scans s where s.id = scan_id and s.user_id = auth.uid())) with check (exists (select 1 from public.scans s where s.id = scan_id and s.user_id = auth.uid()));
create policy scan_urls_delete_own on public.scan_urls for delete to authenticated using (exists (select 1 from public.scans s where s.id = scan_id and s.user_id = auth.uid()));

-- These RPCs are server-only atomic transitions. The FastAPI service uses the
-- service role, while browser roles have no access to guest tables/functions.
create or replace function public.reserve_guest_scan(
  p_guest_session_id uuid,
  p_request_id uuid,
  p_payload_hash text,
  p_scan_limit smallint,
  p_retention_seconds integer,
  p_lease_seconds integer
) returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  existing public.guest_scan_reservations;
  guest_session public.guest_sessions;
  active_count integer;
  new_id uuid := public.gen_random_uuid();
begin
  select * into existing
  from public.guest_scan_reservations
  where guest_session_id = p_guest_session_id and request_id = p_request_id
  for update;

  if found then
    if existing.payload_hash <> p_payload_hash then
      raise exception 'request_id was reused with different input' using errcode = 'P0002';
    end if;
    if existing.status in ('reserved', 'processing')
       and existing.lease_expires_at is not null
       and existing.lease_expires_at < pg_catalog.now() then
      update public.guest_scan_reservations
      set status = 'expired', updated_at = pg_catalog.now()
      where id = existing.id;
      existing.status := 'expired';
    elsif existing.status in ('committed', 'reserved', 'processing') then
      return pg_catalog.jsonb_build_object(
        'id', existing.id, 'status', existing.status,
        'result_json', existing.result_json
      );
    end if;
  end if;

  select * into guest_session
  from public.guest_sessions
  where id = p_guest_session_id and expires_at > pg_catalog.now()
  for update;
  if not found then
    raise exception 'guest session expired' using errcode = 'P0003';
  end if;

  select count(*) into active_count
  from public.guest_scan_reservations
  where guest_session_id = p_guest_session_id
    and status in ('reserved', 'processing');

  if guest_session.committed_scans + active_count >= guest_session.scan_limit then
    raise exception 'Authentication required to continue scanning' using errcode = 'P0001';
  end if;

  if existing.id is not null then
    update public.guest_scan_reservations
    set status = 'reserved',
        result_json = null,
        error_code = null,
        lease_expires_at = pg_catalog.now() + pg_catalog.make_interval(secs => p_lease_seconds),
        retention_expires_at = pg_catalog.now() + pg_catalog.make_interval(secs => p_retention_seconds),
        updated_at = pg_catalog.now()
    where id = existing.id;
    return pg_catalog.jsonb_build_object(
      'id', existing.id, 'status', 'reserved', 'result_json', null
    );
  end if;

  insert into public.guest_scan_reservations (
    id, guest_session_id, request_id, payload_hash, status,
    lease_expires_at, retention_expires_at
  ) values (
    new_id, p_guest_session_id, p_request_id, p_payload_hash, 'reserved',
    pg_catalog.now() + pg_catalog.make_interval(secs => p_lease_seconds),
    pg_catalog.now() + pg_catalog.make_interval(secs => p_retention_seconds)
  );

  return pg_catalog.jsonb_build_object('id', new_id, 'status', 'reserved', 'result_json', null);
end;
$$;

create or replace function public.commit_guest_scan(
  p_guest_session_id uuid,
  p_request_id uuid,
  p_result jsonb
) returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  current_row public.guest_scan_reservations;
begin
  select * into current_row
  from public.guest_scan_reservations
  where guest_session_id = p_guest_session_id and request_id = p_request_id
  for update;
  if not found then raise exception 'guest reservation not found' using errcode = 'P0004'; end if;
  if current_row.status = 'committed' then return coalesce(current_row.result_json, p_result); end if;
  if current_row.status not in ('reserved', 'processing') then
    raise exception 'guest reservation is no longer active' using errcode = 'P0005';
  end if;
  update public.guest_scan_reservations
  set status = 'committed', result_json = p_result, updated_at = pg_catalog.now()
  where id = current_row.id;
  update public.guest_sessions
  set committed_scans = committed_scans + 1, updated_at = pg_catalog.now()
  where id = p_guest_session_id;
  return p_result;
end;
$$;

create or replace function public.rollback_guest_scan(
  p_guest_session_id uuid,
  p_request_id uuid
) returns boolean
language plpgsql
security definer
set search_path = ''
as $$
begin
  update public.guest_scan_reservations
  set status = 'rolled_back', updated_at = pg_catalog.now()
  where guest_session_id = p_guest_session_id
    and request_id = p_request_id
    and status in ('reserved', 'processing');
  return true;
end;
$$;

revoke all on function public.reserve_guest_scan(uuid, uuid, text, smallint, integer, integer) from public, anon, authenticated;
revoke all on function public.commit_guest_scan(uuid, uuid, jsonb) from public, anon, authenticated;
revoke all on function public.rollback_guest_scan(uuid, uuid) from public, anon, authenticated;
grant execute on function public.reserve_guest_scan(uuid, uuid, text, smallint, integer, integer) to service_role;
grant execute on function public.commit_guest_scan(uuid, uuid, jsonb) to service_role;
grant execute on function public.rollback_guest_scan(uuid, uuid) to service_role;
