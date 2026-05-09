-- =============================================================================
-- team-browse: Initial Schema Migration (0001)
-- =============================================================================
-- Multi-tenant schema for the team-browse Electron app.
--
-- Tenant model: companies > teams > profiles (strict tree, one user per company).
-- Roles: owner | team_lead | member.
-- Isolation: Postgres Row-Level Security on every tenant table.
--
-- How to run:
--   1. Open the Supabase SQL Editor.
--   2. Paste this entire file.
--   3. Click Run.
--   4. Verify the tables show up in the Table Editor.
--
-- Post-migration: see the comment block at the bottom for owner setup.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- Extensions
-- -----------------------------------------------------------------------------
create extension if not exists "uuid-ossp";

-- -----------------------------------------------------------------------------
-- Generic updated_at trigger function
-- -----------------------------------------------------------------------------
create or replace function public.set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;


-- =============================================================================
-- Tables
-- =============================================================================

-- companies: tenant root
create table public.companies (
  id          uuid primary key default uuid_generate_v4(),
  name        text not null,
  slug        text not null unique,
  plan        text not null default 'free',
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);
create trigger companies_set_updated_at
  before update on public.companies
  for each row execute function public.set_updated_at();


-- teams: organizational sub-units (optional; a company can run with zero teams)
create table public.teams (
  id          uuid primary key default uuid_generate_v4(),
  company_id  uuid not null references public.companies(id) on delete cascade,
  name        text not null,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now(),
  unique (company_id, name)
);
create index teams_company_idx on public.teams (company_id);
create trigger teams_set_updated_at
  before update on public.teams
  for each row execute function public.set_updated_at();


-- profiles: extends auth.users with app-level info
create table public.profiles (
  id              uuid primary key references auth.users(id) on delete cascade,
  company_id      uuid references public.companies(id) on delete set null,
  team_id         uuid references public.teams(id) on delete set null,
  role            text not null default 'member'
                  check (role in ('owner', 'team_lead', 'member')),
  full_name       text,
  email           text,
  status          text not null default 'pending'
                  check (status in ('pending', 'active', 'suspended')),
  last_active_at  timestamptz,
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now(),
  -- a team_lead must have a team
  check (role <> 'team_lead' or team_id is not null)
);
create index profiles_company_idx on public.profiles (company_id);
create index profiles_team_idx    on public.profiles (team_id);
create trigger profiles_set_updated_at
  before update on public.profiles
  for each row execute function public.set_updated_at();


-- services: per-company catalog of integrated services (Ferdium recipes)
create table public.services (
  id          uuid primary key default uuid_generate_v4(),
  company_id  uuid not null references public.companies(id) on delete cascade,
  name        text not null,
  url         text not null,
  recipe_id   text,
  icon_url    text,
  is_default  boolean not null default true,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);
create index services_company_idx on public.services (company_id);
create trigger services_set_updated_at
  before update on public.services
  for each row execute function public.set_updated_at();


-- team_services: assigns non-default services to specific teams
create table public.team_services (
  team_id     uuid not null references public.teams(id) on delete cascade,
  service_id  uuid not null references public.services(id) on delete cascade,
  created_at  timestamptz not null default now(),
  primary key (team_id, service_id)
);


-- allowlist_entries: company-wide (team_id null) or team-specific allowed domains
create table public.allowlist_entries (
  id          uuid primary key default uuid_generate_v4(),
  company_id  uuid not null references public.companies(id) on delete cascade,
  team_id     uuid references public.teams(id) on delete cascade,
  domain      text not null,
  added_by    uuid references public.profiles(id) on delete set null,
  created_at  timestamptz not null default now(),
  unique (company_id, team_id, domain)
);
create index allowlist_company_team_idx
  on public.allowlist_entries (company_id, team_id);


-- activity_logs: append-only event stream
create table public.activity_logs (
  id           uuid primary key default uuid_generate_v4(),
  company_id   uuid not null references public.companies(id) on delete cascade,
  team_id      uuid references public.teams(id) on delete set null,
  user_id      uuid references public.profiles(id) on delete set null,
  service_id   uuid references public.services(id) on delete set null,
  event_type   text not null,
  url          text,
  duration_ms  integer,
  metadata     jsonb not null default '{}'::jsonb,
  occurred_at  timestamptz not null default now(),
  created_at   timestamptz not null default now()
);
create index activity_logs_company_user_time_idx
  on public.activity_logs (company_id, user_id, occurred_at desc);
create index activity_logs_company_team_time_idx
  on public.activity_logs (company_id, team_id, occurred_at desc);
create index activity_logs_event_type_idx
  on public.activity_logs (event_type);


-- sessions: login periods
create table public.sessions (
  id           uuid primary key default uuid_generate_v4(),
  user_id      uuid not null references public.profiles(id) on delete cascade,
  company_id   uuid not null references public.companies(id) on delete cascade,
  team_id      uuid references public.teams(id) on delete set null,
  started_at   timestamptz not null default now(),
  ended_at     timestamptz,
  device_info  jsonb not null default '{}'::jsonb,
  created_at   timestamptz not null default now()
);
create index sessions_user_time_idx
  on public.sessions (user_id, started_at desc);


-- =============================================================================
-- RLS helper functions
-- =============================================================================
-- security definer + stable so they can run inside policies without recursion

create or replace function public.user_company_id()
returns uuid
language sql
stable
security definer
set search_path = public
as $$
  select company_id from public.profiles where id = auth.uid()
$$;

create or replace function public.user_team_id()
returns uuid
language sql
stable
security definer
set search_path = public
as $$
  select team_id from public.profiles where id = auth.uid()
$$;

create or replace function public.user_role()
returns text
language sql
stable
security definer
set search_path = public
as $$
  select role from public.profiles where id = auth.uid()
$$;


-- =============================================================================
-- Auto-create profile on signup
-- =============================================================================
-- When a row is inserted into auth.users (via Supabase Auth signup), we
-- automatically create a matching profile row with status = 'pending'.
-- An owner then assigns the user to a company/team/role.

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, email, status)
  values (new.id, new.email, 'pending');
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();


-- =============================================================================
-- Row-Level Security
-- =============================================================================

alter table public.companies         enable row level security;
alter table public.teams             enable row level security;
alter table public.profiles          enable row level security;
alter table public.services          enable row level security;
alter table public.team_services     enable row level security;
alter table public.allowlist_entries enable row level security;
alter table public.activity_logs     enable row level security;
alter table public.sessions          enable row level security;


-- ----- companies -----
create policy "users see own company" on public.companies
  for select using (id = public.user_company_id());

create policy "owners update own company" on public.companies
  for update using (
    id = public.user_company_id()
    and public.user_role() = 'owner'
  );


-- ----- teams -----
create policy "users see company teams" on public.teams
  for select using (company_id = public.user_company_id());

create policy "owners manage teams" on public.teams
  for all
  using (
    company_id = public.user_company_id()
    and public.user_role() = 'owner'
  )
  with check (
    company_id = public.user_company_id()
    and public.user_role() = 'owner'
  );


-- ----- profiles -----
-- Users always see and update their own profile (even before company assigned).
create policy "users see own profile" on public.profiles
  for select using (id = auth.uid());

create policy "users update own profile" on public.profiles
  for update using (id = auth.uid());

-- Team leads see members of their team.
create policy "team leads see their team" on public.profiles
  for select using (
    public.user_role() = 'team_lead'
    and company_id = public.user_company_id()
    and team_id = public.user_team_id()
  );

-- Owners see and manage every profile in their company.
create policy "owners see all company profiles" on public.profiles
  for select using (
    public.user_role() = 'owner'
    and company_id = public.user_company_id()
  );

create policy "owners manage company profiles" on public.profiles
  for all
  using (
    public.user_role() = 'owner'
    and company_id = public.user_company_id()
  )
  with check (
    public.user_role() = 'owner'
    and company_id = public.user_company_id()
  );


-- ----- services -----
create policy "users see company services" on public.services
  for select using (company_id = public.user_company_id());

create policy "owners manage services" on public.services
  for all
  using (
    company_id = public.user_company_id()
    and public.user_role() = 'owner'
  )
  with check (
    company_id = public.user_company_id()
    and public.user_role() = 'owner'
  );


-- ----- team_services -----
create policy "users see relevant team services" on public.team_services
  for select using (
    exists (
      select 1 from public.teams t
      where t.id = team_services.team_id
        and t.company_id = public.user_company_id()
    )
    and (
      public.user_role() = 'owner'
      or team_id = public.user_team_id()
    )
  );

create policy "owners manage team services" on public.team_services
  for all
  using (
    public.user_role() = 'owner'
    and exists (
      select 1 from public.teams t
      where t.id = team_services.team_id
        and t.company_id = public.user_company_id()
    )
  )
  with check (
    public.user_role() = 'owner'
    and exists (
      select 1 from public.teams t
      where t.id = team_services.team_id
        and t.company_id = public.user_company_id()
    )
  );


-- ----- allowlist_entries -----
create policy "users see company allowlist" on public.allowlist_entries
  for select using (company_id = public.user_company_id());

create policy "owners manage allowlist" on public.allowlist_entries
  for all
  using (
    company_id = public.user_company_id()
    and public.user_role() = 'owner'
  )
  with check (
    company_id = public.user_company_id()
    and public.user_role() = 'owner'
  );


-- ----- activity_logs -----
-- Members see their own, team_leads see their team, owners see all in company.
create policy "users see own activity" on public.activity_logs
  for select using (
    user_id = auth.uid()
    and company_id = public.user_company_id()
  );

create policy "team leads see team activity" on public.activity_logs
  for select using (
    public.user_role() = 'team_lead'
    and company_id = public.user_company_id()
    and team_id = public.user_team_id()
  );

create policy "owners see company activity" on public.activity_logs
  for select using (
    public.user_role() = 'owner'
    and company_id = public.user_company_id()
  );

-- Inserts: any authenticated user can log their own activity.
create policy "users insert own activity" on public.activity_logs
  for insert with check (
    user_id = auth.uid()
    and company_id = public.user_company_id()
  );


-- ----- sessions -----
create policy "users see own sessions" on public.sessions
  for select using (
    user_id = auth.uid()
    and company_id = public.user_company_id()
  );

create policy "team leads see team sessions" on public.sessions
  for select using (
    public.user_role() = 'team_lead'
    and company_id = public.user_company_id()
    and team_id = public.user_team_id()
  );

create policy "owners see company sessions" on public.sessions
  for select using (
    public.user_role() = 'owner'
    and company_id = public.user_company_id()
  );

create policy "users insert own session" on public.sessions
  for insert with check (
    user_id = auth.uid()
    and company_id = public.user_company_id()
  );

create policy "users update own session" on public.sessions
  for update using (user_id = auth.uid());


-- =============================================================================
-- Seed: Slaterock Automation
-- =============================================================================
-- Founding company. The owner profile is set in a separate step after you
-- sign up via Supabase Auth (see comment block at the bottom).

insert into public.companies (id, name, slug, plan)
values (
  '11111111-1111-1111-1111-111111111111',
  'Slaterock Automation',
  'slaterock',
  'free'
);

-- Default service catalog. Update URLs to your actual instances later.
insert into public.services (company_id, name, url, recipe_id, is_default) values
  ('11111111-1111-1111-1111-111111111111', 'Flowlu',          'https://slaterock.flowlu.com',     'flowlu',          true),
  ('11111111-1111-1111-1111-111111111111', 'Gmail',           'https://mail.google.com',          'gmail',           true),
  ('11111111-1111-1111-1111-111111111111', 'Google Calendar', 'https://calendar.google.com',      'google-calendar', true),
  ('11111111-1111-1111-1111-111111111111', 'Google Chat',     'https://chat.google.com',          'google-chat',     true);


-- =============================================================================
-- Post-migration: claim ownership of Slaterock
-- =============================================================================
-- After this migration runs successfully:
--
-- 1. In the Supabase dashboard: Authentication > Users > "Add user".
--    Enter your email and a temporary password.
--    The on_auth_user_created trigger auto-creates a profile row for you
--    with status='pending' and no company assigned.
--
-- 2. Find your auth user ID: Authentication > Users > click your user > copy UID.
--
-- 3. Open SQL Editor and run this, replacing YOUR_UID and YOUR_NAME:
--
--    update public.profiles
--    set company_id = '11111111-1111-1111-1111-111111111111',
--        role       = 'owner',
--        full_name  = 'YOUR_NAME',
--        status     = 'active'
--    where id = 'YOUR_UID';
--
-- You're now the owner of Slaterock Automation.
-- =============================================================================
