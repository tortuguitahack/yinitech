-- Run in the canonical Supabase project, after reviewing the schema.
-- No payment method can set paid status from browser input.

create table if not exists public.yinitech_orders (
  id uuid primary key default gen_random_uuid(),
  product_id text not null,
  product_name text not null,
  customer_email text not null,
  amount_cents integer not null check (amount_cents > 0),
  currency text not null default 'usd' check (currency = 'usd'),
  payment_method text not null check (payment_method in ('stripe', 'bank_transfer', 'altoke', 'crypto')),
  status text not null default 'pending' check (status in ('pending', 'paid', 'cancelled', 'failed', 'review')),
  stripe_session_id text unique,
  provider_payment_id text unique,
  created_at timestamptz not null default now(),
  paid_at timestamptz
);

create table if not exists public.yinitech_webhook_events (
  provider text not null check (provider in ('stripe', 'whop')),
  event_id text not null,
  event_type text not null,
  received_at timestamptz not null default now(),
  processed_at timestamptz,
  processing_result text,
  primary key (provider, event_id)
);

alter table public.yinitech_orders enable row level security;
alter table public.yinitech_webhook_events enable row level security;

-- Do not create public policies for these tables. Backend service role only.
-- Protect service-role key and database access using Supabase project settings.
