// 일룸 수면과학연구소 시험성적서 시스템 — 백엔드 서버
//
// 브라우저는 이 서버의 /api/... 만 호출한다. 데이터베이스 접속정보(DATABASE_URL)는
// 서버에만 있으며 브라우저로 절대 내려가지 않는다.
//
//   브라우저 ──/api/...──> 이 서버 ──DATABASE_URL──> Postgres
//
// 로그인 확인·권한 검사도 모두 이 서버에서 한다(브라우저 우회 불가).

const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { Pool, types } = require('pg');
const pdfParse = require('pdf-parse');
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  WidthType, BorderStyle, AlignmentType, HeadingLevel, ShadingType, ImageRun,
  Footer, PageNumber,
} = require('docx');

// Postgres BIGINT(oid 20)은 기본적으로 문자열로 오므로 숫자로 파싱한다
// (타임스탬프 밀리초 값이 문자열이면 화면에서 Invalid Date 가 된다)
types.setTypeParser(20, (v) => (v === null ? null : Number(v)));

const app = express();
const PORT = Number(process.env.PORT || 8080);
const TABLES = ['reports', 'requests', 'accounts', 'settings', 'extcerts'];
const SIGNKEY_ROW_ID = '__session_secret';   // 서명키를 보관하는 설정 행 이름(값 자체는 실행 중에 자동 생성)
const SESSION_COOKIE = 'iloom_sess';
const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12시간

app.use(express.json({ limit: '40mb' }));
app.disable('x-powered-by');

// 기본 보안 헤더
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'same-origin');
  next();
});

// 로그인 시도 제한 (같은 아이디·접속지에서 연속 실패가 쌓이면 잠시 막는다)
const LOGIN_MAX_FAILS = 10;
const LOGIN_LOCK_MS = 5 * 60 * 1000;
const loginFails = new Map();
function loginKey(req, id) {
  return String(id) + '|' + (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '');
}
function loginLocked(key) {
  const e = loginFails.get(key);
  if (!e) return 0;
  if (e.until && e.until > Date.now()) return Math.ceil((e.until - Date.now()) / 1000);
  if (e.until) loginFails.delete(key);
  return 0;
}
function loginFailed(key) {
  const e = loginFails.get(key) || { n: 0, until: 0 };
  e.n += 1;
  if (e.n >= LOGIN_MAX_FAILS) { e.until = Date.now() + LOGIN_LOCK_MS; e.n = 0; }
  loginFails.set(key, e);
}
function loginSucceeded(key) {
  loginFails.delete(key);
}

// ── 데이터베이스 ─────────────────────────────────────────
const DATABASE_URL = process.env.DATABASE_URL || '';
let pool = null;

if (DATABASE_URL) {
  const isLocal = /@(localhost|127\.0\.0\.1)[:/]/.test(DATABASE_URL);
  pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: isLocal ? false : { rejectUnauthorized: false },
    max: Number(process.env.DB_POOL_MAX || 5),
    idleTimeoutMillis: 30000,
  });
  pool.on('error', (e) => console.error('[db] 유휴 연결 오류:', e.message));
} else {
  console.warn('[db] DATABASE_URL 이 없습니다 — 화면은 뜨지만 데이터를 읽고 쓸 수 없습니다.');
}

function dbReady(res) {
  if (pool) return true;
  res.status(503).json({ error: 'DB_NOT_CONFIGURED', message: '데이터베이스 접속 정보가 설정되지 않았습니다. 관리자에게 문의해주세요.' });
  return false;
}

async function initSchema() {
  if (!pool) return;
  const sqlPath = path.join(__dirname, 'db', 'schema.sql');
  try {
    const sql = fs.readFileSync(sqlPath, 'utf8');
    await pool.query(sql);
    console.log('[db] 표 준비 완료');
  } catch (e) {
    console.error('[db] 표 준비 실패:', e.message);
  }
}

// ── 세션 (HMAC 서명 쿠키, HttpOnly) ──────────────────────
let sessionSecret = process.env.SESSION_SECRET || '';

async function loadSessionSecret() {
  if (sessionSecret) return;
  if (pool) {
    try {
      const { rows } = await pool.query('SELECT data FROM settings WHERE id = $1', [SIGNKEY_ROW_ID]);
      if (rows[0] && rows[0].data && rows[0].data.value) {
        sessionSecret = rows[0].data.value;
        return;
      }
      const generated = crypto.randomBytes(48).toString('hex');
      await pool.query(
        'INSERT INTO settings (id, data, updated_at) VALUES ($1, $2, now()) ON CONFLICT (id) DO NOTHING',
        [SIGNKEY_ROW_ID, JSON.stringify({ value: generated })]
      );
      const again = await pool.query('SELECT data FROM settings WHERE id = $1', [SIGNKEY_ROW_ID]);
      sessionSecret = (again.rows[0] && again.rows[0].data && again.rows[0].data.value) || generated;
      return;
    } catch (e) {
      console.warn('[session] 서명키를 저장하지 못했습니다:', e.message);
    }
  }
  sessionSecret = crypto.randomBytes(48).toString('hex');
  console.warn('[session] 임시 서명키 사용 — 서버가 재시작되면 모두 다시 로그인해야 합니다.');
}

function b64u(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function unb64u(str) {
  return Buffer.from(String(str).replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
}
function sign(payload) {
  return crypto.createHmac('sha256', sessionSecret).update(payload).digest('hex');
}
function makeSession(user) {
  const body = b64u(JSON.stringify({ id: user.id, name: user.name, role: user.role, exp: Date.now() + SESSION_TTL_MS }));
  return body + '.' + sign(body);
}
function readSession(req) {
  const raw = req.headers.cookie || '';
  const hit = raw.split(';').map((s) => s.trim()).find((s) => s.startsWith(SESSION_COOKIE + '='));
  if (!hit) return null;
  const token = decodeURIComponent(hit.slice(SESSION_COOKIE.length + 1));
  const dot = token.lastIndexOf('.');
  if (dot < 1) return null;
  const body = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  const expect = sign(body);
  if (sig.length !== expect.length) return null;
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expect))) return null;
  try {
    const data = JSON.parse(unb64u(body));
    if (!data.exp || data.exp < Date.now()) return null;
    return data;
  } catch (e) {
    return null;
  }
}
function setSessionCookie(res, user) {
  const parts = [
    SESSION_COOKIE + '=' + encodeURIComponent(makeSession(user)),
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    'Max-Age=' + Math.floor(SESSION_TTL_MS / 1000),
  ];
  if (process.env.COOKIE_INSECURE !== '1') parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}
function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', SESSION_COOKIE + '=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0');
}

function requireLogin(req, res, next) {
  const s = readSession(req);
  if (!s) return res.status(401).json({ error: 'NOT_LOGGED_IN', message: '로그인이 필요합니다.' });
  req.user = s;
  next();
}
function requireAdmin(req, res, next) {
  if (req.user && req.user.role === '관리자') return next();
  return res.status(403).json({ error: 'FORBIDDEN', message: '관리자만 할 수 있습니다.' });
}

// ── 비밀번호 ─────────────────────────────────────────────
// 저장 형식: scrypt$<salt>$<hash>
// 예전 형식도 로그인은 되게 하고(성공 시 자동으로 최신 형식으로 올림):
//   · 64자리 16진수 = 예전 브라우저 SHA-256 해시
//   · 그 외 문자열   = 예전 평문
function hashPw(plain) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(String(plain), salt, 64);
  return 'scrypt$' + salt.toString('hex') + '$' + hash.toString('hex');
}
function sha256Hex(s) {
  return crypto.createHash('sha256').update(String(s)).digest('hex');
}
function eq(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}
// 반환: { ok, needsUpgrade }
function verifyPw(plain, stored) {
  if (!stored) return { ok: false, needsUpgrade: false };
  const s = String(stored);
  if (s.startsWith('scrypt$')) {
    const [, saltHex, hashHex] = s.split('$');
    if (!saltHex || !hashHex) return { ok: false, needsUpgrade: false };
    let calc;
    try {
      calc = crypto.scryptSync(String(plain), Buffer.from(saltHex, 'hex'), 64).toString('hex');
    } catch (e) {
      return { ok: false, needsUpgrade: false };
    }
    return { ok: eq(calc, hashHex), needsUpgrade: false };
  }
  if (/^[0-9a-f]{64}$/.test(s)) return { ok: eq(sha256Hex(plain), s), needsUpgrade: true };
  return { ok: eq(plain, s), needsUpgrade: true };
}

// ── 계정 조회 ────────────────────────────────────────────
async function getAccountRow(id) {
  const { rows } = await pool.query('SELECT id, data FROM accounts WHERE id = $1', [id]);
  return rows[0] || null;
}
async function countAccounts() {
  const { rows } = await pool.query('SELECT count(*)::int AS n FROM accounts');
  return rows[0] ? rows[0].n : 0;
}
// jsonb 로 넣을 값은 반드시 문자열로 직렬화한다.
// (배열을 그대로 넘기면 Postgres 가 배열 리터럴로 해석해 "invalid input syntax for type json" 이 난다 —
//  이 앱의 규격 목록·의뢰항목이 배열이라 실제로 저장이 깨진다.)
function toJsonParam(v) {
  return v === undefined || v === null ? null : JSON.stringify(v);
}

async function saveAccount(id, data) {
  await pool.query(
    'INSERT INTO accounts (id, data, updated_at) VALUES ($1, $2, now()) ON CONFLICT (id) DO UPDATE SET data = $2, updated_at = now()',
    [id, toJsonParam(data)]
  );
}
// 비밀번호를 뺀 형태로만 브라우저에 보낸다
function publicAccount(data) {
  const out = Object.assign({}, data || {});
  const had = !!out.pw;
  delete out.pw;
  out.hasPassword = had;
  return out;
}

// ══════════════════════════════════════════════════════════
// API — 인증
// ══════════════════════════════════════════════════════════
app.get('/api/health', (req, res) => {
  res.json({ ok: true, db: !!pool });
});

app.get('/api/session', (req, res) => {
  const s = readSession(req);
  if (!s) return res.status(401).json({ error: 'NOT_LOGGED_IN' });
  res.json({ user: { id: s.id, name: s.name, role: s.role } });
});

app.post('/api/login', async (req, res) => {
  if (!dbReady(res)) return;
  const id = String((req.body && req.body.id) || '').trim();
  const pw = String((req.body && req.body.pw) || '');
  if (!id || !pw) return res.status(400).json({ error: 'MISSING', message: '아이디와 비밀번호를 입력해주세요.' });
  const key = loginKey(req, id);
  const wait = loginLocked(key);
  if (wait) {
    return res.status(429).json({ error: 'TOO_MANY_ATTEMPTS', message: '로그인 시도가 너무 많았어요. ' + Math.ceil(wait / 60) + '분 뒤에 다시 시도해주세요.' });
  }
  try {
    if ((await countAccounts()) === 0) {
      return res.status(409).json({ error: 'SETUP_REQUIRED', setup: true, message: '등록된 계정이 없습니다. 첫 관리자 계정을 만들어주세요.' });
    }
    const row = await getAccountRow(id);
    if (!row) {
      loginFailed(key);
      return res.status(401).json({ error: 'BAD_CREDENTIALS', message: '아이디 또는 비밀번호가 올바르지 않습니다.' });
    }
    const data = row.data || {};
    const v = verifyPw(pw, data.pw);
    if (!v.ok) {
      loginFailed(key);
      return res.status(401).json({ error: 'BAD_CREDENTIALS', message: '아이디 또는 비밀번호가 올바르지 않습니다.' });
    }
    if (v.needsUpgrade) {
      data.pw = hashPw(pw);
      await saveAccount(id, data);
    }
    loginSucceeded(key);
    const user = { id: data.id || id, name: data.name || id, role: data.role || '시험원' };
    setSessionCookie(res, user);
    res.json({ user: user });
  } catch (e) {
    console.error('[login]', e.message);
    res.status(500).json({ error: 'SERVER_ERROR', message: '로그인 처리 중 오류가 났습니다.' });
  }
});

app.post('/api/logout', (req, res) => {
  clearSessionCookie(res);
  res.json({ ok: true });
});

// 계정이 하나도 없을 때만 허용 — 첫 관리자 만들기
app.post('/api/setup-admin', async (req, res) => {
  if (!dbReady(res)) return;
  const id = String((req.body && req.body.id) || '').trim();
  const pw = String((req.body && req.body.pw) || '');
  const name = String((req.body && req.body.name) || '').trim() || id;
  if (!id || pw.length < 4) return res.status(400).json({ error: 'MISSING', message: '아이디와 4자 이상 비밀번호가 필요합니다.' });
  try {
    if ((await countAccounts()) > 0) {
      return res.status(409).json({ error: 'ALREADY_SETUP', message: '이미 계정이 있어 최초 설정을 할 수 없습니다.' });
    }
    const data = { id: id, name: name, role: '관리자', pw: hashPw(pw) };
    await saveAccount(id, data);
    const user = { id: id, name: name, role: '관리자' };
    setSessionCookie(res, user);
    res.json({ user: user });
  } catch (e) {
    console.error('[setup-admin]', e.message);
    res.status(500).json({ error: 'SERVER_ERROR', message: '설정 중 오류가 났습니다.' });
  }
});

// 본인 비밀번호 변경
app.post('/api/change-password', requireLogin, async (req, res) => {
  if (!dbReady(res)) return;
  const curPw = String((req.body && req.body.curPw) || '');
  const newPw = String((req.body && req.body.newPw) || '');
  if (newPw.length < 4) return res.status(400).json({ error: 'TOO_SHORT', message: '새 비밀번호는 4자 이상이어야 합니다.' });
  try {
    const row = await getAccountRow(req.user.id);
    if (!row) return res.status(404).json({ error: 'NOT_FOUND', message: '계정을 찾을 수 없습니다.' });
    const data = row.data || {};
    if (!verifyPw(curPw, data.pw).ok) {
      return res.status(400).json({ error: 'BAD_CURRENT', message: '현재 비밀번호가 올바르지 않습니다.' });
    }
    data.pw = hashPw(newPw);
    await saveAccount(req.user.id, data);
    res.json({ ok: true });
  } catch (e) {
    console.error('[change-password]', e.message);
    res.status(500).json({ error: 'SERVER_ERROR', message: '변경 중 오류가 났습니다.' });
  }
});

// 관리자가 남의 비밀번호를 지정(초기화)
app.post('/api/accounts/set-password', requireLogin, requireAdmin, async (req, res) => {
  if (!dbReady(res)) return;
  const id = String((req.body && req.body.id) || '').trim();
  const newPw = String((req.body && req.body.newPw) || '');
  if (!id || newPw.length < 4) return res.status(400).json({ error: 'MISSING', message: '아이디와 4자 이상 비밀번호가 필요합니다.' });
  try {
    const row = await getAccountRow(id);
    if (!row) return res.status(404).json({ error: 'NOT_FOUND', message: '계정을 찾을 수 없습니다.' });
    const data = row.data || {};
    data.pw = hashPw(newPw);
    await saveAccount(id, data);
    res.json({ ok: true });
  } catch (e) {
    console.error('[set-password]', e.message);
    res.status(500).json({ error: 'SERVER_ERROR', message: '변경 중 오류가 났습니다.' });
  }
});

// ══════════════════════════════════════════════════════════
// API — 계정 목록 (비밀번호는 절대 내려보내지 않는다)
// ══════════════════════════════════════════════════════════
app.get('/api/accounts', requireLogin, async (req, res) => {
  if (!dbReady(res)) return;
  try {
    const { rows } = await pool.query('SELECT id, data, updated_at FROM accounts ORDER BY id');
    res.json(rows.map((r) => ({ id: r.id, data: publicAccount(r.data), updated_at: r.updated_at })));
  } catch (e) {
    console.error('[accounts:get]', e.message);
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

// 계정 추가·수정 (관리자만). 비밀번호는 별도 API 로만 다룬다.
app.post('/api/accounts', requireLogin, requireAdmin, async (req, res) => {
  if (!dbReady(res)) return;
  const body = req.body || {};
  const id = String(body.id || (body.data && body.data.id) || '').trim();
  const incoming = body.data || {};
  const newPw = body.pw ? String(body.pw) : '';
  if (!id) return res.status(400).json({ error: 'MISSING', message: '아이디가 필요합니다.' });
  try {
    const existing = await getAccountRow(id);
    const data = {
      id: id,
      name: String(incoming.name || id),
      role: String(incoming.role || '시험원'),
    };
    // 기존 비밀번호는 보존 — 새 값이 왔을 때만 바꾼다
    if (newPw) {
      if (newPw.length < 4) return res.status(400).json({ error: 'TOO_SHORT', message: '비밀번호는 4자 이상이어야 합니다.' });
      data.pw = hashPw(newPw);
    } else if (existing && existing.data && existing.data.pw) {
      data.pw = existing.data.pw;
    }
    await saveAccount(id, data);
    res.json({ ok: true, created: !existing });
  } catch (e) {
    console.error('[accounts:post]', e.message);
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

// 계정 목록 전체 맞추기 (관리자만) — 이름·권한만 반영하고 비밀번호는 보존한다
app.put('/api/accounts', requireLogin, requireAdmin, async (req, res) => {
  if (!dbReady(res)) return;
  const list = Array.isArray(req.body && req.body.list) ? req.body.list : null;
  if (!list) return res.status(400).json({ error: 'MISSING', message: '계정 목록이 필요합니다.' });
  try {
    const { rows } = await pool.query('SELECT id, data FROM accounts');
    const before = new Map(rows.map((r) => [r.id, r.data || {}]));
    const keep = new Set();
    for (const item of list) {
      const id = String((item && item.id) || '').trim();
      if (!id) continue;
      keep.add(id);
      const prev = before.get(id) || {};
      const data = {
        id: id,
        name: String(item.name || prev.name || id),
        role: String(item.role || prev.role || '시험원'),
      };
      if (prev.pw) data.pw = prev.pw;
      await saveAccount(id, data);
    }
    for (const id of before.keys()) {
      if (!keep.has(id)) await pool.query('DELETE FROM accounts WHERE id = $1', [id]);
    }
    res.json({ ok: true, count: keep.size });
  } catch (e) {
    console.error('[accounts:put]', e.message);
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

app.delete('/api/accounts', requireLogin, requireAdmin, async (req, res) => {
  if (!dbReady(res)) return;
  const id = String(req.query.id || '').trim();
  if (!id) return res.status(400).json({ error: 'MISSING' });
  if (id === req.user.id) return res.status(400).json({ error: 'SELF_DELETE', message: '본인 계정은 삭제할 수 없습니다.' });
  try {
    await pool.query('DELETE FROM accounts WHERE id = $1', [id]);
    res.json({ ok: true });
  } catch (e) {
    console.error('[accounts:delete]', e.message);
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

// ══════════════════════════════════════════════════════════
// API — 일반 데이터 (성적서·의뢰서·설정) : 로그인 필요
// ══════════════════════════════════════════════════════════
function dataTable(name) {
  return TABLES.includes(name) && name !== 'accounts';
}

app.get('/api/:table(reports|requests|settings|extcerts)', requireLogin, async (req, res) => {
  if (!dbReady(res)) return;
  const table = req.params.table;
  if (!dataTable(table)) return res.status(404).json({ error: 'NO_TABLE' });
  try {
    const id = req.query.id ? String(req.query.id) : '';
    const q = id
      ? await pool.query(`SELECT id, data, updated_at FROM ${table} WHERE id = $1`, [id])
      : await pool.query(`SELECT id, data, updated_at FROM ${table}`);
    let rows = q.rows;
    // 서버 내부용 설정(서명키 등)은 브라우저에 내려보내지 않는다
    if (table === 'settings') rows = rows.filter((r) => !String(r.id).startsWith('__'));
    res.json(rows);
  } catch (e) {
    console.error('[' + table + ':get]', e.message);
    res.status(500).json({ error: 'SERVER_ERROR', message: e.message });
  }
});

app.post('/api/:table(reports|requests|settings|extcerts)', requireLogin, async (req, res) => {
  if (!dbReady(res)) return;
  const table = req.params.table;
  if (!dataTable(table)) return res.status(404).json({ error: 'NO_TABLE' });
  const body = req.body || {};
  const id = String(body.id || '').trim();
  if (!id) return res.status(400).json({ error: 'MISSING_ID' });
  if (table === 'settings' && id.startsWith('__')) return res.status(400).json({ error: 'RESERVED_ID' });
  try {
    await pool.query(
      `INSERT INTO ${table} (id, data, updated_at) VALUES ($1, $2, now())
       ON CONFLICT (id) DO UPDATE SET data = $2, updated_at = now()`,
      [id, toJsonParam(body.data)]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error('[' + table + ':post]', e.message);
    res.status(500).json({ error: 'SERVER_ERROR', message: e.message });
  }
});

app.delete('/api/:table(reports|requests|settings|extcerts)', requireLogin, async (req, res) => {
  if (!dbReady(res)) return;
  const table = req.params.table;
  if (!dataTable(table)) return res.status(404).json({ error: 'NO_TABLE' });
  const id = String(req.query.id || '').trim();
  if (!id) return res.status(400).json({ error: 'MISSING_ID' });
  if (table === 'settings' && id.startsWith('__')) return res.status(400).json({ error: 'RESERVED_ID' });
  try {
    await pool.query(`DELETE FROM ${table} WHERE id = $1`, [id]);
    res.json({ ok: true });
  } catch (e) {
    console.error('[' + table + ':delete]', e.message);
    res.status(500).json({ error: 'SERVER_ERROR', message: e.message });
  }
});

// ══════════════════════════════════════════════════════════
// API — 제품사용확인서(퍼시스 납품용 증명서) PDF에서 "시험 항목별 결과 종합"
// 요약표만 추출한다.
//
// 예전에 성적서 PDF 전체(서술형 보고서 포함)를 표/텍스트 블록으로 통째로
// 재구성하려다가, 표 인식이 미세하게 어긋나는 문제로 사용자가 기능 전체를
// 롤백한 적이 있다(2026-08-31). 이번에는 범위를 "구분/시험항목/시험규격/
// 결과/판정" 요약표 한 개로 좁히고 — 이 표는 시험기관 PDF에 이미 한 줄에
// 한 항목씩 정리되어 있어 훨씬 안정적으로 뽑을 수 있다 — 추출 결과는
// 절대 그대로 보고서에 반영하지 않고, 화면에서 사람이 검토·수정한 뒤에만
// 쓰도록 프런트에서 강제한다.
// ══════════════════════════════════════════════════════════

// pdf-parse의 기본 렌더러는 같은 줄(y좌표)의 글자를 구분자 없이 이어붙여서
// 표의 여러 칸이 한 덩어리로 뭉개진다. 글자를 y좌표로 먼저 줄로 묶고, 같은
// 줄 안에서 x좌표 간격이 벌어지면 칸 경계로 보고 나눠준다.
function renderPageWithColumns(pageData) {
  const renderOptions = { normalizeWhitespace: false, disableCombineTextItems: false };
  return pageData.getTextContent(renderOptions).then((textContent) => {
    const items = textContent.items
      .map((it) => ({ str: it.str, x: it.transform[4], y: it.transform[5], w: it.width || it.str.length * 4 }))
      .filter((it) => it.str && it.str.trim());

    const Y_TOL = 2.5;
    const rows = [];
    items.forEach((it) => {
      let row = rows.find((r) => Math.abs(r.y - it.y) <= Y_TOL);
      if (!row) { row = { y: it.y, items: [] }; rows.push(row); }
      row.items.push(it);
    });
    rows.sort((a, b) => b.y - a.y); // PDF 좌표는 위로 갈수록 y가 커짐

    const GAP_TOL = 8; // pt 단위 — 이보다 간격이 벌어지면 다른 칸으로 봄
    const CELL_SEP = '\u0001';
    const lines = rows.map((row) => {
      const its = row.items.slice().sort((a, b) => a.x - b.x);
      const cells = [];
      let cur = '';
      let prevEndX = null;
      its.forEach((it) => {
        if (prevEndX !== null && it.x - prevEndX > GAP_TOL) {
          cells.push(cur.trim());
          cur = '';
        }
        cur += it.str;
        prevEndX = it.x + it.w;
      });
      if (cur.trim()) cells.push(cur.trim());
      return cells.join(CELL_SEP);
    }).filter(Boolean);

    return lines.join('\n');
  });
}

// 페이지 머리글/바닥글 등 시험기관 PDF마다 반복되는 잡음 줄 — 항목으로 잘못 섞이지 않게 걸러낸다
function isNoiseLine(text) {
  const t = text.trim();
  if (!t) return true;
  if (/PAGE\s*\d+\s*OF\s*\d+/i.test(t)) return true;
  if (/^QPF-\d/i.test(t)) return true;
  if (/KOTITI\s*Testing/i.test(t)) return true;
  if (/^\d{10,}$/.test(t)) return true; // 성적서번호만 단독으로 찍힌 머리글 줄
  if (/^Primary Contact/i.test(t)) return true;
  if (/^-\s*시험결과\s*기록\s*완료\s*-$/.test(t)) return true;
  return false;
}

// 항목 구분(카테고리)을 항목명 키워드로 추정한다 — 시험기관 PDF에는 이 분류가
// 문자로 적혀있지 않으므로 어디까지나 "제안"이며, 화면에서 사람이 확인·수정해야 한다.
const CATEGORY_KEYWORDS = [
  [/아릴아민|pH|포름알데히드|염소화페놀|방염제|유해원소|유해염료/, '유해물질'],
  [/밀도|파열강도|인장강도|인열강도|필링|투습도|공기투과도|치수변화/, '물성'],
  [/마찰\s*견뢰도|땀\s*견뢰도|물\s*견뢰도|견뢰도/, '견뢰도'],
  [/혼용률/, '조성'],
  [/방염시험|가연성|연소/, '난연'],
];
function guessCategory(itemName) {
  const hit = CATEGORY_KEYWORDS.find(([re]) => re.test(itemName));
  return hit ? hit[1] : '';
}

// 항목 제목/표 안 KS 규격 텍스트 중, "KS ...년도" 형태의 규격 코드만 뽑아낸다.
// 규격이 여러 개 섞여 있으면(예: "KS K0210:2023/KS K0210-1:2026") 전부 " / "로 이어붙인다.
// (탐욕적으로 매칭해 "KS K0642.8.14.1A법:2022"처럼 중간에 다른 숫자가 섞여도
//  진짜 연도(맨 뒤 4자리)까지 놓치지 않고 잡는다)
function extractStandardCodes(text) {
  const matches = text.match(/KS[\s\S]{0,45}\d{4}/g) || [];
  const cleaned = matches.map((m) => m.replace(/\s+/g, ' ').trim());
  return [...new Set(cleaned)].join(' / ');
}

// "검출안됨:5mg/kg미만" 같은 각주성 정의 줄인지 판단한다. 콜론이 있어도 "KS" 규격
// 인용문(예: "KS K0739:2017")은 legend가 아니므로 제외한다.
function isLegendLine(text) {
  if (!/[:：]/.test(text)) return false;
  if (/KS/.test(text)) return false;
  return true;
}

// 값처럼 생긴 셀인지 판단한다 — 항목 제목/각주 텍스트와 실제 시험결과 값을 구분하는 핵심 신호.
function looksLikeValue(v) {
  const s = (v || '').trim();
  if (!s) return false;
  if (/^[\d.,\s]+(mm\/sec|g\/m²·?24h?ours?|N|%|급)?$/.test(s)) return true;
  if (/^검출\s*안\s*됨$/.test(s)) return true;
  if (/^\d+-\d+$/.test(s)) return true; // 등급 "4-5"
  if (/발화되지\s*않음|발화됨/.test(s)) return true;
  if (/^[가-힣A-Za-z]+\s*\d+%$/.test(s)) return true; // "폴리에스터 100%"
  return false;
}

app.post('/api/extract-summary-table', requireLogin, async (req, res) => {
  try {
    const raw = String((req.body || {}).pdfBase64 || '');
    const b64 = raw.replace(/^data:application\/pdf[^,]*,/, '');
    if (!b64) return res.status(400).json({ error: 'MISSING_PDF' });
    const buf = Buffer.from(b64, 'base64');
    const data = await pdfParse(buf, { pagerender: renderPageWithColumns });
    const allLines = (data.text || '')
      .split(/\r?\n/)
      .map((l) => l.split('\u0001').map((c) => c.trim()).filter(Boolean))
      .filter((cells) => cells.length)
      .filter((cells) => !isNoiseLine(cells.join(' ')));

    let certNoGuess = '';
    const certMatch = (data.text || '').match(/(?:KOTITI\s*No\.?|성적서\s*NO\.?)\s*([0-9A-Za-z()]+)/i);
    if (certMatch) certNoGuess = certMatch[1];

    // 방식 1) "구분/시험항목/시험규격/결과/판정"이 한 표에 다 정리된 요약표가 있으면 그걸 그대로 쓴다.
    const summaryHeaderIdx = allLines.findIndex((cells) => {
      const joined = cells.join(' ');
      return joined.includes('구분') && joined.includes('판정');
    });
    const items = [];
    if (summaryHeaderIdx >= 0) {
      let lastCategory = '';
      for (let i = summaryHeaderIdx + 1; i < allLines.length; i += 1) {
        const cells = allLines[i];
        if (cells.length < 3) break;
        let row = cells;
        if (row.length === 4) row = [lastCategory, ...row];
        if (row.length < 5) break;
        const [category, item, standard, result, verdict] = row;
        lastCategory = category || lastCategory;
        items.push({ category: category || lastCategory, item: item || '', standard: standard || '', result: result || '', verdict: verdict || '' });
      }
    }

    // 방식 2) (실제 시험기관 PDF는 대부분 이 형태) 항목마다 "항목명 + (KS 규격)" 제목 아래
    // "구분/시험결과/기준" 3칸 표가 따로따로 있다 — 이 작은 표들을 순서대로 훑어서 항목별로 모은다.
    // "판정"(적합/부적합)과 "구분"(유해물질/물성 등 분류)은 원문에 글자로 적혀있지 않으므로
    // 절대 지어내지 않는다 — 구분은 항목명으로 추정한 "제안값"만 넣고, 판정은 항상 비워서
    // 사람이 직접 판단해 채우도록 한다.
    // "기준" 칸이 아예 없는 항목(예: 방염시험 — 구분/시험결과 2칸뿐)도 있어 2칸/3칸 머리글을 모두 인정한다
    const headerIdxs = [];
    allLines.forEach((cells, i) => {
      const isHeader3 = cells.length === 3 && cells[0] === '구분' && /결과/.test(cells[1]) && cells[2] === '기준';
      const isHeader2 = cells.length === 2 && cells[0] === '구분' && /결과/.test(cells[1]);
      if (isHeader3 || isHeader2) headerIdxs.push(i);
    });

    if (headerIdxs.length) {
      headerIdxs.forEach((h, hi) => {
        const nextH = hi + 1 < headerIdxs.length ? headerIdxs[hi + 1] : allLines.length;

        // 제목 구간: 이 표 머리글 바로 위쪽에서 시작해 위로 거슬러 올라가며 모은다.
        // "주)" 각주를 만나면(=이전 항목 몫) 멈추고, "검출안됨:5mg/kg미만" 같은 legend 줄은
        // 건너뛰고 계속 올라가며, 값처럼 생긴 줄을 만나면(=이전 항목의 실제 데이터) 그 자리에서 멈춘다.
        const prevEnd = hi === 0 ? 0 : headerIdxs[hi - 1] + 1;
        const titleLines = [];
        for (let i = h - 1; i >= prevEnd; i -= 1) {
          const cells = allLines[i];
          const text = cells.join(' ');
          if (/^주\)/.test(text)) break; // 각주를 만나면 그 위는 이전 항목 몫이니 멈춤
          if (isLegendLine(text)) continue; // legend 줄은 제목이 아니니 건너뛰고 계속 올라감
          const lastCell = cells[cells.length - 1] || '';
          if (cells.length <= 2 && looksLikeValue(lastCell)) break; // 이전 항목의 실제 데이터를 만나면 멈춤
          titleLines.unshift(text);
          if (titleLines.length >= 4) break; // 제목이 4줄을 넘어가진 않는다고 봄
        }
        const titleText = titleLines.join(' ');
        const standard = extractStandardCodes(titleText);
        // 제목에서 괄호로 시작하는(=규격 인용) 줄은 빼고, 나머지를 항목명으로 쓴다.
        // 쉼표 뒤는 단위 표기(예: "아릴아민, mg/kg"의 ", mg/kg")라 항목명에서는 뺀다.
        let itemName = titleLines.filter((l) => !l.trim().startsWith('(')).join(' ').trim() || titleText.replace(/\([\s\S]*$/, '').trim();
        itemName = itemName.split(',')[0].trim();

        // 데이터 구간: 표 머리글 다음 줄부터 시작해서, "값처럼 생기지 않은" 줄을 만나는 순간 멈춘다
        // (그 줄부터는 각주나 다음 항목 제목이 시작된 것으로 본다 — 다음 표 머리글까지 무작정
        // 다 긁어오면 그 사이에 낀 각주·다음 항목 제목까지 데이터로 잘못 섞여 들어간다).
        const dataRows = [];
        let criterion = ''; // "주)" 각주에 적힌 기준(예: pH 4.0~7.5)을 참고용으로 같이 보여준다
        for (let i = h + 1; i < nextH; i += 1) {
          const cells = allLines[i];
          const text = cells.join(' ');
          if (/^\([A-Z](?:,\s*[A-Z])*\)$/.test(text)) continue; // "(A)" 등 시료 반복 표시
          if (/^주\)/.test(text)) { criterion = text.replace(/^주\)\s*/, ''); break; } // 각주 = 기준, 여기서 데이터는 끝
          if (isLegendLine(text)) break; // "검출안됨:5mg/kg미만" 같은 legend도 데이터 끝 신호
          if (!cells.length) continue;
          const lastCell = cells[cells.length - 1] || '';
          if (!looksLikeValue(lastCell)) break; // 값처럼 안 생겼으면 다음 항목 제목이 시작된 것
          if (cells.length === 1) dataRows.push({ label: '', value: cells[0] });
          else dataRows.push({ label: cells[0], value: cells[1] });
        }

        if (!itemName || !dataRows.length) return; // 제목이나 데이터를 못 찾으면 이 표는 건너뜀

        // 결과값 정리: 값이 1개면 그대로, 2개면 "라벨 값 / 라벨 값"으로, 전부 같으면 개수만 덧붙이고,
        // 제각각이면 전부 나열한다 — 어느 경우든 원문 값을 그대로 쓰고 새로 지어내지 않는다.
        let result;
        const values = dataRows.map((r) => r.value);
        const allSame = values.every((v) => v === values[0]);
        if (dataRows.length === 1) {
          result = dataRows[0].value;
        } else if (allSame) {
          result = `${values[0]} (전체 ${dataRows.length}건 동일)`;
        } else if (dataRows.length === 2 && dataRows[0].label && dataRows[1].label) {
          result = `${dataRows[0].label} ${dataRows[0].value} / ${dataRows[1].label} ${dataRows[1].value}`;
        } else {
          result = dataRows.map((r) => (r.label ? `${r.label}: ${r.value}` : r.value)).join('; ');
        }
        // "검출안됨"은 유해물질 시험에서 워낙 자주(수십 건) 반복돼 그대로 나열하면 표가 지저분해지니
        // 요청대로 PASS로 축약한다 — 그 외 실측값(숫자/등급 등)은 값 그대로 둔다.
        if (/^검출\s*안\s*됨(\s*\(전체\s*\d+건\s*동일\))?$/.test(result)) result = 'PASS';

        items.push({ category: guessCategory(itemName), item: itemName, standard, criterion, result, verdict: '' });
      });
    }

    res.json({ ok: true, items, certNoGuess, mode: summaryHeaderIdx >= 0 ? 'summary-table' : (headerIdxs.length ? 'per-item-tables' : 'none') });
  } catch (e) {
    console.error('[extract-summary-table]', e.message);
    res.status(500).json({ error: 'SERVER_ERROR', message: e.message });
  }
});

// ══════════════════════════════════════════════════════════
// API — 제품사용확인서 보고서를 .docx 파일로 생성
// (화면에서 사람이 검토·확정한 값만 받아서 문서를 만든다 — 이 엔드포인트는
// PDF를 다시 읽지 않는다)
// ══════════════════════════════════════════════════════════
function extCellText(text, opts) {
  return new Paragraph({
    alignment: (opts && opts.align) || AlignmentType.CENTER,
    children: [new TextRun({ text: String(text == null ? '' : text), bold: !!(opts && opts.bold), color: (opts && opts.color) || undefined, size: (opts && opts.size) || 20 })],
  });
}
function extCell(text, opts) {
  return new TableCell({
    width: { size: (opts && opts.width) || 2000, type: WidthType.DXA },
    shading: opts && opts.shade ? { type: ShadingType.CLEAR, fill: opts.shade } : undefined,
    verticalAlign: 'center',
    children: [extCellText(text, opts)],
  });
}
function infoRow(label, value) {
  return new TableRow({
    children: [
      extCell(label, { width: 2200, shade: 'F3F4F6', bold: true, align: AlignmentType.CENTER }),
      extCell(value, { width: 6800, align: AlignmentType.LEFT }),
    ],
  });
}

// public/ 아래 고정 이미지(로고·서명 도장)를 읽어 docx ImageRun이 쓸 수 있는 Buffer로 바꾼다.
// 이 앱의 다른 성적서들과 동일하게, 기술책임자(강지영)·품질책임자(장성진) 서명 도장은
// public/jy-sign.png · public/sj-sign.png를 그대로 쓴다 — 요청으로 새로 받을 필요가 없다.
function publicImage(filename) {
  try {
    return { buffer: fs.readFileSync(path.join(__dirname, 'public', filename)), type: 'png' };
  } catch (e) {
    return null;
  }
}

function bulletPara(text) {
  return new Paragraph({ spacing: { after: 60 }, children: [new TextRun({ text: '▪ ' + text, bold: true })] });
}
function bodyPara(text) {
  return new Paragraph({ spacing: { after: 160 }, children: [new TextRun({ text })] });
}
// docx-js는 TextRun 안의 "\n"을 줄바꿈으로 처리하지 않으므로, 줄 단위로 나눠 break로 이어붙인다
function multiLinePara(text) {
  const lines = String(text).split('\n');
  return new Paragraph({
    spacing: { after: 160 },
    children: lines.map((line, i) => new TextRun(i === 0 ? { text: line } : { text: line, break: 1 })),
  });
}

// "iloom → 제조·공급 → FURSYS" 관계도를 표(칸 3개짜리 1행)로 표현한다.
function supplyDiagramTable() {
  function box(logoFile, logoWidth, logoHeight, sub1, sub2, shade) {
    const logo = publicImage(logoFile);
    return new TableCell({
      width: { size: 3000, type: WidthType.DXA },
      shading: { type: ShadingType.CLEAR, fill: shade },
      margins: { top: 200, bottom: 200, left: 100, right: 100 },
      children: [
        new Paragraph({
          alignment: AlignmentType.CENTER,
          spacing: { after: 60 },
          children: logo ? [new ImageRun({ data: logo.buffer, type: logo.type, transformation: { width: logoWidth, height: logoHeight } })] : [new TextRun({ text: '(로고)', size: 20 })],
        }),
        new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 20 }, children: [new TextRun({ text: sub1, bold: true, size: 18 })] }),
        new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: sub2, size: 16, color: '6B7280' })] }),
      ],
    });
  }
  const arrowCell = new TableCell({
    width: { size: 1200, type: WidthType.DXA },
    verticalAlign: 'center',
    children: [
      new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: '▶', size: 28, color: 'C81E2C' })] }),
      new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: '제조·공급', size: 14 })] }),
    ],
  });
  return new Table({
    width: { size: 7200, type: WidthType.DXA },
    rows: [new TableRow({ children: [
      box('iloom-logo.png', 140, 49, '제조 · 시험 주체', '일룸 매트리스사업부 품질보증팀', 'FFF1F0'),
      arrowCell,
      box('fursys-logo.png', 140, 58, '브랜드 · 공급처', '퍼시스 매트리스로 판매', 'F3F4F6'),
    ] })],
  });
}

async function buildExtCertDocxBuffer(f) {
  const items = Array.isArray(f.items) ? f.items : [];
  const badCount = items.filter((it) => String(it.verdict || '').trim() === '부적합').length;
  const overallVerdict = items.length === 0 ? '판정 항목 없음' : (badCount > 0 ? `부적합 ${badCount}건 있음` : '적합 (Pass)');
  const fabric = f.targetFabric || '해당 원단/자재';
  const agency = f.testAgency || '공인시험기관';

  const infoTable = new Table({
    width: { size: 9000, type: WidthType.DXA },
    rows: [
      infoRow('문서번호', f.docNo),
      infoRow('작성일', f.createdDate),
      infoRow('작성부서', f.department || '일룸 매트리스사업부 품질보증팀'),
      infoRow('작성자', f.author),
      infoRow('대상 제품', f.targetProduct),
      infoRow('대상 원단/자재', f.targetFabric),
      infoRow('시험 기관', f.testAgency),
      infoRow('성적서 번호', f.certNo),
    ],
  });

  const roleHeader = new TableRow({
    tableHeader: true,
    children: ['구분', '주체', '역할'].map((h) => extCell(h, { width: 2400, shade: 'F3F4F6', bold: true })),
  });
  const roleRows = [
    ['제조', '일룸 매트리스사업부', '매트리스 제조 및 원단·자재 사양 결정'],
    ['품질보증', '일룸 매트리스사업부 품질보증팀', '시험 계획 수립, 시험 의뢰 및 결과 검증'],
    ['시험 수행', agency, '공인시험기관'],
    ['공급 · 판매', '퍼시스(FURSYS)', '일룸 제조 제품을 퍼시스 매트리스로 공급'],
  ].map(([a, b, c]) => new TableRow({ children: [extCell(a, { width: 2400 }), extCell(b, { width: 2400 }), extCell(c, { width: 2400, align: AlignmentType.LEFT })] }));
  const roleTable = new Table({ width: { size: 7200, type: WidthType.DXA }, rows: [roleHeader, ...roleRows] });

  const resultHeader = new TableRow({
    tableHeader: true,
    children: ['구분', '시험 항목', '시험 규격', '결과', '판정'].map((h) =>
      extCell(h, { width: 1800, shade: 'FEE2E2', bold: true })),
  });
  const resultRows = items.map((it) => new TableRow({
    children: [
      extCell(it.category, { width: 1400 }),
      extCell(it.item, { width: 2400, align: AlignmentType.LEFT }),
      extCell(it.standard, { width: 2000 }),
      extCell(it.result, { width: 1600 }),
      extCell(it.verdict, { width: 1200, bold: true, color: String(it.verdict || '').trim() === '부적합' ? 'DC2626' : undefined }),
    ],
  }));
  const resultTable = new Table({ width: { size: 9000, type: WidthType.DXA }, rows: [resultHeader, ...resultRows] });

  const h2 = (text) => new Paragraph({ heading: HeadingLevel.HEADING_2, spacing: { before: 300, after: 120 }, children: [new TextRun({ text, bold: true })] });
  const body = (text) => new Paragraph({ spacing: { after: 120 }, children: [new TextRun({ text })] });

  // 확인(서명)란 — 기술책임자 강지영 · 품질책임자 장성진은 이 앱의 다른 성적서와 동일하게 고정된 서명을 쓴다.
  // 서명 이미지가 가로로 넓고 얇은 비율이라, 정사각형으로 강제하면 위아래에 빈 여백이 크게 남는다 —
  // 실제 이미지 가로세로 비율대로 높이를 계산해서 그 여백을 없앤다.
  function signCell(label, name, signFile) {
    const img = publicImage(signFile);
    const targetWidth = 190;
    let height = targetWidth;
    if (img) {
      try {
        const w = img.buffer.readUInt32BE(16);
        const h = img.buffer.readUInt32BE(20);
        if (w && h) height = Math.round((targetWidth * h) / w);
      } catch (e) { /* 크기 계산 실패 시 정사각형으로 대체 */ }
    }
    return new TableCell({
      width: { size: 3600, type: WidthType.DXA },
      margins: { top: 40, bottom: 40 },
      children: [
        new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 40 }, children: [new TextRun({ text: `${label} (${name})`, bold: true, size: 18 })] }),
        img
          ? new Paragraph({ alignment: AlignmentType.CENTER, children: [new ImageRun({ data: img.buffer, type: img.type, transformation: { width: targetWidth, height } })] })
          : new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: '(서명 없음)', size: 16, color: '9CA3AF' })] }),
      ],
    });
  }
  const signTable = new Table({
    width: { size: 7200, type: WidthType.DXA },
    rows: [new TableRow({ children: [
      signCell('기술책임자', '강지영', 'jy-sign.png'),
      signCell('품질책임자', '장성진', 'sj-sign.png'),
    ] })],
  });

  const pageFooter = new Footer({
    children: [new Paragraph({
      alignment: AlignmentType.CENTER,
      children: [
        new TextRun({ children: [PageNumber.CURRENT], size: 18, color: '9CA3AF' }),
        new TextRun({ text: ' / ', size: 18, color: '9CA3AF' }),
        new TextRun({ children: [PageNumber.TOTAL_PAGES], size: 18, color: '9CA3AF' }),
      ],
    })],
  });

  const doc = new Document({
    sections: [{
      properties: {
        page: {
          size: { width: 11907, height: 16840 }, // A4
          margin: { top: 1600, bottom: 1400, left: 1400, right: 1400 },
        },
      },
      footers: { default: pageFooter },
      children: [
        new Paragraph({
          alignment: AlignmentType.CENTER,
          spacing: { after: 240 },
          border: {
            top: { style: BorderStyle.SINGLE, size: 8, color: 'E39A9A', space: 8 },
            bottom: { style: BorderStyle.SINGLE, size: 8, color: 'E39A9A', space: 8 },
          },
          children: [new TextRun({ text: '퍼시스 매트리스 시험 결과 보고서', bold: true, size: 30 })],
        }),
        infoTable,
        new Paragraph({ text: '', spacing: { after: 200 } }),

        h2('1. 개요'),
        bulletPara('목적'),
        bodyPara(f.overviewText || `본 보고서는 "퍼시스 매트리스" 제출용으로, 제품에 적용되는 매트리스 원단/자재 '${fabric}'의 성능을 국내·해외 시험 기준에 따라 검증하고 그 결과를 증빙하기 위해 작성되었습니다.`),
        bulletPara('제품 및 시험 주체'),
        bodyPara('퍼시스 매트리스는 일룸(iloom) 매트리스사업부에서 제조한 매트리스를 사용하고 있습니다. 이에 따라 원단 및 소재의 안전성 시험은 제조 주체인 일룸이 직접 계획·의뢰하여 공인시험기관에서 수행하며, 그 결과를 퍼시스에 제공합니다.'),
        bulletPara('대상'),
        multiLinePara(`대상 제품 : ${f.targetProduct || ''}\n시험 대상 : ${fabric}\n시험 기관 : ${agency}`),

        h2('2. 제조 및 공급 관계'),
        supplyDiagramTable(),
        new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 60, after: 200 }, children: [new TextRun({ text: '[그림 1] 퍼시스 매트리스 제조 · 공급 체계', italics: true, size: 16, color: '6B7280' })] }),
        roleTable,
        new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 60, after: 200 }, children: [new TextRun({ text: '[표 1] 주체별 역할 구분', italics: true, size: 16, color: '6B7280' })] }),
        body('퍼시스 매트리스는 퍼시스그룹 내 일룸 매트리스사업부에서 제조·공급하는 매트리스를 적용합니다. 따라서 본 보고서의 시험 결과는 퍼시스 매트리스에 그대로 적용됩니다.'),

        h2('3. 시험 결과 요약'),
        new Paragraph({ spacing: { after: 100 }, children: [new TextRun({ text: `[표 2] 시험 항목별 결과 종합 (성적서 NO. ${f.certNo || ''})`, italics: true, size: 18 })] }),
        resultTable,
        h2('4. 결론'),
        body(`종합 판정: ${overallVerdict}`),
        h2('5. 첨부'),
        body(`${agency} 시험성적서 NO. ${f.certNo || ''} 1부`),

        new Paragraph({ text: '', spacing: { before: 300, after: 100 } }),
        new Paragraph({ spacing: { after: 100 }, children: [new TextRun({ text: '확인', bold: true, size: 20 })] }),
        signTable,
      ],
    }],
  });

  return Packer.toBuffer(doc);
}

app.post('/api/extcert-docx', requireLogin, async (req, res) => {
  try {
    const buf = await buildExtCertDocxBuffer(req.body || {});
    const filename = `${(req.body && req.body.docNo) || '제품사용확인서'}.docx`;
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
    res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(filename)}`);
    res.send(buf);
  } catch (e) {
    console.error('[extcert-docx]', e.message);
    res.status(500).json({ error: 'SERVER_ERROR', message: e.message });
  }
});

// ══════════════════════════════════════════════════════════
// API — QR 진위확인 (로그인 없이 열람, 읽기 전용)
// ══════════════════════════════════════════════════════════
// QR 에 담긴 확인코드(t)를 서버가 직접 검증한다.
// 코드가 맞지 않으면 성적서 내용을 내려보내지 않는다(번호만 알아내 몰래 열람하는 것을 막는다).
// 화면에 표시하는 항목만 내려보낸다(필요 이상 공개 금지).
function verifyToken(data) {
  const str = [data.receiptNo || '', data.issuedDate || '', data.sampleName || '', data.tester || '', data.issuedAt || ''].join('||');
  return crypto.createHash('sha256').update(str).digest('hex').slice(0, 24);
}

app.get('/api/verify', async (req, res) => {
  if (!dbReady(res)) return;
  const id = String(req.query.id || '').trim();
  const token = String(req.query.t || '').trim();
  if (!id) return res.status(400).json({ error: 'MISSING_ID' });
  try {
    const { rows } = await pool.query('SELECT id, data FROM reports WHERE id = $1', [id]);
    if (!rows[0] || !rows[0].data) return res.json({ status: 'not-found' });
    const data = rows[0].data;
    if (!token || !eq(token, verifyToken(data))) return res.json({ status: 'token-mismatch' });
    res.json({
      status: 'ok',
      issued: !!data.issued,
      report: {
        receiptNo: data.receiptNo || '',
        issuedDate: data.issuedDate || '',
        sampleName: data.sampleName || '',
        requestDept: data.requestDept || '',
        purpose: data.purpose || '',
        issuedAt: data.issuedAt || data.savedAt || '',
        reissued: !!(data.unlockHistory && data.unlockHistory.length > 0),
        kolasFormat: !!data.kolasFormat,
        testItems: (data.tests || []).map((t) => t.name).filter(Boolean).join(', '),
      },
    });
  } catch (e) {
    console.error('[verify]', e.message);
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

// ── 정적 파일 (공개 전용 폴더만) ─────────────────────────
app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html' }));

app.use('/api', (req, res) => res.status(404).json({ error: 'NO_ROUTE' }));

// ── 시작 ─────────────────────────────────────────────────
(async () => {
  await initSchema();
  await loadSessionSecret();
  app.listen(PORT, '0.0.0.0', () => {
    console.log('[server] 준비 완료 — 포트 ' + PORT + (pool ? '' : ' (데이터베이스 미설정)'));
  });
})();
