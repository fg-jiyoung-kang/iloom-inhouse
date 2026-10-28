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

-- 외부증빙(퍼시스 납품용 증명서) — 시험 항목별 결과 요약표 + 상단 정보
CREATE TABLE IF NOT EXISTS extcerts (
  id         text PRIMARY KEY,
  data       jsonb,
  updated_at timestamptz DEFAULT now()
);

-- 로그인 시도 기록(성공/실패 모두) — 접속 추적용, 추가만 하고 수정하지 않는 로그
CREATE TABLE IF NOT EXISTS login_log (
  id         bigserial PRIMARY KEY,
  account_id text,
  success    boolean NOT NULL,
  ip         text,
  user_agent text,
  source     text, -- 접속 도메인(사내 서버 vs Vercel 등 어느 배포로 들어왔는지 구분)
  created_at timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_login_log_created_at ON login_log (created_at DESC);
ALTER TABLE login_log ADD COLUMN IF NOT EXISTS source text;

-- 로그인 2차 인증(이메일) 대기 코드 — 계정당 1개, 새로 요청하면 덮어쓴다
CREATE TABLE IF NOT EXISTS login_2fa (
  account_id text PRIMARY KEY,
  code_hash  text NOT NULL,
  expires_at timestamptz NOT NULL,
  attempts   integer NOT NULL DEFAULT 0,
  created_at timestamptz DEFAULT now()
);

-- 활동 기록(생성/수정/발행/잠금/수정요청/삭제/출력) — 쌓이기만 하는 로그
CREATE TABLE IF NOT EXISTS activity_log (
  id           bigserial PRIMARY KEY,
  account_id   text,
  action       text NOT NULL,
  target_table text,
  target_id    text,
  detail       text,
  source       text, -- 접속 도메인(출력/다운로드 등 활동이 어느 배포에서 일어났는지)
  ip           text,
  created_at   timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_activity_log_created_at ON activity_log (created_at DESC);
ALTER TABLE activity_log ADD COLUMN IF NOT EXISTS source text;
ALTER TABLE activity_log ADD COLUMN IF NOT EXISTS ip text;
