-- ─────────────────────────────────────────────────────────────────
-- Wealth Manager — Supabase Schema
-- Run this in: Supabase Dashboard → SQL Editor → New Query → Run
-- ─────────────────────────────────────────────────────────────────

-- Users
create table if not exists users (
  id                    text primary key,
  first_name            text not null,
  last_name             text not null,
  email                 text unique not null,
  password_hash         text not null,
  role                  text not null default 'user',
  plan                  text default 'free',
  status                text default 'active',
  company               text,
  preferred_name        text,
  advisor_id            text references users(id),
  stripe_customer_id    text,
  stripe_subscription_id text,
  created_at            timestamptz default now(),
  updated_at            timestamptz default now()
);

-- Properties
create table if not exists properties (
  id            text primary key,
  user_id       text not null references users(id) on delete cascade,
  address       text,
  suburb        text,
  postcode      text,
  state         text,
  type          text,
  beds          numeric,
  baths         numeric,
  cars          numeric,
  land          numeric,
  purchase_price numeric,
  purchase_date text,
  value         numeric,
  valued_date   text,
  loan          numeric,
  rate          numeric,
  repayment     numeric,
  loan_type     text,
  lender        text,
  fixed_until   text,
  weekly_rent   numeric,
  vacancy       numeric,
  tenant        text,
  lease_expiry  text,
  rates         numeric,
  insurance     numeric,
  mgmt          numeric,
  maintenance   numeric,
  strata        numeric,
  water         numeric,
  notes         text,
  image         text,
  owners        jsonb,
  created_at    timestamptz default now(),
  updated_at    timestamptz default now()
);

-- Income log
create table if not exists income_log (
  id          text primary key,
  property_id text not null references properties(id) on delete cascade,
  user_id     text not null references users(id) on delete cascade,
  date        text,
  type        text,
  description text,
  amount      numeric default 0,
  created_at  timestamptz default now()
);

-- Expenses
create table if not exists expenses (
  id          text primary key,
  property_id text not null references properties(id) on delete cascade,
  user_id     text not null references users(id) on delete cascade,
  date        text,
  category    text,
  description text,
  amount      numeric default 0,
  created_at  timestamptz default now()
);

-- Messages
create table if not exists messages (
  id      text primary key,
  from_id text not null references users(id),
  to_id   text not null references users(id),
  body    text not null,
  ts      timestamptz default now(),
  read    boolean default false
);

-- Broadcasts
create table if not exists broadcasts (
  id         text primary key,
  message    text not null,
  date       text,
  active     boolean default false,
  posted_by  text references users(id),
  created_at timestamptz default now()
);

-- Invites
create table if not exists invites (
  id             text primary key,
  code           text unique not null,
  advisor_name   text,
  advisor_email  text,
  status         text default 'pending',
  used_by        text references users(id),
  used_at        timestamptz,
  created_at     timestamptz default now()
);

-- Blog posts
create table if not exists blog_posts (
  id         text primary key,
  title      text,
  category   text,
  author     text,
  date       text,
  content    text,
  excerpt    text,
  featured   boolean default false,
  published  boolean default false,
  created_at timestamptz default now()
);

-- Disable Row Level Security (we use service_role key from backend — backend enforces auth)
alter table users       disable row level security;
alter table properties  disable row level security;
alter table income_log  disable row level security;
alter table expenses    disable row level security;
alter table messages    disable row level security;
alter table broadcasts  disable row level security;
alter table invites     disable row level security;
alter table blog_posts  disable row level security;
