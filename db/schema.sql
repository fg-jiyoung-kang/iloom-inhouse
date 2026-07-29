-- 표가 없으면 만든다(이미 있으면 아무것도 하지 않음).
-- 회사 Supabase 전용 스키마(app_260723_tbx7) 사용
SET search_path TO app_260723_tbx7, public;

CREATE TABLE IF NOT EXISTS reports (
  id         text PRIMARY KEY,
  data       jsonb,
  updated_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS requests (
  id         text PRIMARY KEY,
  data       jsonb,
  updated_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS accounts (
  id         text PRIMARY KEY,
  data       jsonb,
  updated_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS settings (
  id         text PRIMARY KEY,
  data       jsonb,
  updated_at timestamptz DEFAULT now()
);
