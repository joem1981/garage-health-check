-- Run this once against your Postgres database to set up the tables.

CREATE TABLE IF NOT EXISTS garages (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  stripe_customer_id TEXT,
  stripe_subscription_id TEXT,
  subscription_status TEXT NOT NULL DEFAULT 'inactive',
  free_reports_used INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS inspections (
  id SERIAL PRIMARY KEY,
  garage_id INTEGER NOT NULL REFERENCES garages(id) ON DELETE CASCADE,
  share_token TEXT UNIQUE NOT NULL,
  vehicle_reg TEXT,
  customer_name TEXT,
  data JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_inspections_garage ON inspections(garage_id);
CREATE INDEX IF NOT EXISTS idx_inspections_token ON inspections(share_token);
