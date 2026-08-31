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

// Postgres BIGINT(oid 20)은 기본적으로 문자열로 오므로 숫자로 파싱한다
// (타임스탬프 밀리초 값이 문자열이면 화면에서 Invalid Date 가 된다)
types.setTypeParser(20, (v) => (v === null ? null : Number(v)));

const app = express();
const PORT = Number(process.env.PORT || 8080);
const TABLES = ['reports', 'requests', 'accounts', 'settings'];
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

app.get('/api/:table(reports|requests|settings)', requireLogin, async (req, res) => {
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

app.post('/api/:table(reports|requests|settings)', requireLogin, async (req, res) => {
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

app.delete('/api/:table(reports|requests|settings)', requireLogin, async (req, res) => {
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
