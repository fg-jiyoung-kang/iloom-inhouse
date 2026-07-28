-- 표가 없으면 만든다(이미 있으면 아무것도 하지 않음).
-- 기존 Supabase 프로젝트의 표와 같은 구조라, 접속 문자열만 넣으면 기존 데이터를 그대로 이어 쓴다.

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
