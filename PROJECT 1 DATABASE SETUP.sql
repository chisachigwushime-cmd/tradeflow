-- ==========================================================
-- TradeFlow — Owner authentication & organization schema
-- Run this once in Supabase: SQL Editor → New query → paste all → Run
-- ==========================================================

create extension if not exists pgcrypto;

create table if not exists organizations (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  owner_id uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

create table if not exists profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  organization_id uuid references organizations(id) on delete cascade,
  role text not null default 'owner' check (role in (
    'owner','administrator','sales_manager','sales_staff',
    'finance','inventory_manager','customer_support','operations','customer'
  )),
  full_name text,
  created_at timestamptz not null default now()
);

alter table organizations enable row level security;
alter table profiles enable row level security;

-- A user can only see the organization they belong to.
create policy "Users can view their own organization"
  on organizations for select
  using (id = (select organization_id from profiles where id = auth.uid()));

-- Only the owner can update their organization's settings.
create policy "Owner can update own organization"
  on organizations for update
  using (owner_id = auth.uid());

-- A user can only see their own profile row.
create policy "Users can view their own profile"
  on profiles for select
  using (id = auth.uid());

-- Deliberately no INSERT policies on either table for regular users.
-- Organization + owner-profile creation happens ONLY through the
-- function below, which is the single, audited path to becoming an
-- owner — this is what enforces "one primary owner per organization"
-- at the database level, not just by hiding a button in the UI.

create or replace function create_organization(org_name text)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  new_org_id uuid;
begin
  if org_name is null or length(trim(org_name)) = 0 then
    raise exception 'Organization name is required';
  end if;

  -- A signed-in user can only ever go through this once. Trying again
  -- (e.g. by replaying the request) is refused, not silently allowed.
  if exists (select 1 from profiles where id = auth.uid()) then
    raise exception 'This account already belongs to an organization';
  end if;

  insert into organizations (name, owner_id)
  values (trim(org_name), auth.uid())
  returning id into new_org_id;

  insert into profiles (id, organization_id, role)
  values (auth.uid(), new_org_id, 'owner');

  return new_org_id;
end;
$$;

grant execute on function create_organization(text) to authenticated;
