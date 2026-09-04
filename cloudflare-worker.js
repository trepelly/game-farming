// MSU Proxy - Cloudflare Worker
// Cho phép fetch msu.io API từ browser (bỏ qua CORS)

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PATCH, OPTIONS',
  'Access-Control-Allow-Headers': '*',
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS });
    }

    // ══════════════ AUTH + GIST ROUTES (bảo vệ bằng session HMAC) ══════════════
    // POST  /auth   {username, password}  → xác thực server-side, trả {token, role, viewAll, ...}
    // GET   /gist   (Bearer session)      → đọc Gist — cần đăng nhập
    // PATCH /gist   (Bearer session admin)→ ghi Gist — chỉ admin
    // Cần env: GIST_TOKEN (đã có), SESSION_SECRET (chuỗi ngẫu nhiên dài, tự đặt)

    const te = new TextEncoder();
    const b64u = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
    const b64uStr = s => b64u(te.encode(s));
    const fromB64u = s => { s = s.replace(/-/g,'+').replace(/_/g,'/'); while (s.length % 4) s += '='; return atob(s); };

    async function hmacKey() {
      return crypto.subtle.importKey('raw', te.encode(env.SESSION_SECRET || ''), { name:'HMAC', hash:'SHA-256' }, false, ['sign','verify']);
    }
    async function signSession(payload) {
      const body = b64uStr(JSON.stringify(payload));
      const sig  = await crypto.subtle.sign('HMAC', await hmacKey(), te.encode(body));
      return body + '.' + b64u(sig);
    }
    async function verifySession(token) {
      if (!token || token.indexOf('.') < 0) return null;
      const [body, sig] = token.split('.');
      const sigBytes = Uint8Array.from(fromB64u(sig), c => c.charCodeAt(0));
      const ok = await crypto.subtle.verify('HMAC', await hmacKey(), sigBytes, te.encode(body));
      if (!ok) return null;
      let p; try { p = JSON.parse(fromB64u(body)); } catch { return null; }
      if (!p.exp || Date.now() > p.exp) return null;
      return p;
    }
    async function sha256Hex(str) {
      const buf = await crypto.subtle.digest('SHA-256', te.encode(str));
      return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2,'0')).join('');
    }
    // PBKDF2-SHA256 (100k vòng — mức tối đa Cloudflare cho phép) → hex
    const PBKDF2_ITER = 100000;
    async function pbkdf2Hex(password, saltHex, iterations) {
      const salt = Uint8Array.from(saltHex.match(/.{2}/g).map(h => parseInt(h, 16)));
      const key  = await crypto.subtle.importKey('raw', te.encode(password), 'PBKDF2', false, ['deriveBits']);
      const bits = await crypto.subtle.deriveBits({ name:'PBKDF2', hash:'SHA-256', salt, iterations: iterations || PBKDF2_ITER }, key, 256);
      return [...new Uint8Array(bits)].map(b => b.toString(16).padStart(2,'0')).join('');
    }
    const randomSaltHex = () => [...crypto.getRandomValues(new Uint8Array(16))].map(b => b.toString(16).padStart(2,'0')).join('');
    const json = (obj, status=200) => new Response(JSON.stringify(obj), { status, headers: { 'Content-Type':'application/json', ...CORS } });
    const GIST_ID   = env.GIST_ID; // BẮT BUỘC đặt trong env — không hardcode để không lộ trên repo
    const ghHeaders = { 'Authorization': 'token ' + (env.GIST_TOKEN||''), 'Accept': 'application/vnd.github.v3+json', 'User-Agent': 'msu-proxy' };
    async function readGist() {
      const r = await fetch('https://api.github.com/gists/' + GIST_ID, { headers: ghHeaders });
      return { status: r.status, body: await r.text() };
    }

    if (url.pathname === '/auth' && request.method === 'POST') {
      if (!env.GIST_TOKEN)      return json({ error: 'GIST_TOKEN chưa cấu hình' }, 500);
      if (!GIST_ID)             return json({ error: 'GIST_ID chưa cấu hình trong Worker env' }, 500);
      if (!env.SESSION_SECRET)  return json({ error: 'SESSION_SECRET chưa cấu hình' }, 500);
      let creds; try { creds = await request.json(); } catch { return json({ error: 'Body không hợp lệ' }, 400); }
      const { username, password } = creds || {};
      if (!username || !password) return json({ error: 'Thiếu username/password' }, 400);
      const g = await readGist();
      if (g.status !== 200) return json({ error: 'Không đọc được dữ liệu người dùng' }, 502);
      let users = [];
      try { users = (JSON.parse(JSON.parse(g.body).files['team-users.json'].content).users) || []; } catch {}
      const u = users.find(x => x.username === username);
      let ok = false, migrated = false;
      if (u && u.salt && u.hash) {
        // ── Chế độ mới: PBKDF2 + salt riêng từng user ──
        ok = (await pbkdf2Hex(password, u.salt, u.iter || PBKDF2_ITER)) === u.hash;
      } else if (u && u.password) {
        // ── Chế độ cũ: SHA-256 không salt → nếu đúng thì NÂNG CẤP record ngay ──
        ok = (await sha256Hex(password)) === u.password;
        if (ok) {
          u.salt = randomSaltHex();
          u.iter = PBKDF2_ITER;
          u.hash = await pbkdf2Hex(password, u.salt, u.iter);
          delete u.password; // xoá hash cũ không salt
          migrated = true;
        }
      }
      if (!ok) return json({ error: 'Sai tên đăng nhập hoặc mật khẩu' }, 401);
      if (migrated) {
        // Ghi lại file users với record đã nâng cấp (best-effort — lỗi ghi không chặn đăng nhập)
        try {
          await fetch('https://api.github.com/gists/' + GIST_ID, {
            method: 'PATCH',
            headers: { ...ghHeaders, 'Content-Type': 'application/json' },
            body: JSON.stringify({ files: { 'team-users.json': { content: JSON.stringify({ users }, null, 2) } } }),
          });
        } catch {}
      }
      const payload = { u: u.username, role: u.role || 'member', viewAll: !!u.viewAll,
                        player: u.player || null, players: u.players || null,
                        exp: Date.now() + 12 * 3600 * 1000 };
      const token = await signSession(payload);
      return json({ token, user: payload });
    }

    if (url.pathname === '/gist') {
      if (!env.GIST_TOKEN) return json({ error: 'GIST_TOKEN chưa cấu hình' }, 500);
      if (!GIST_ID)        return json({ error: 'GIST_ID chưa cấu hình trong Worker env' }, 500);
      // Xác thực session (nếu SESSION_SECRET chưa đặt, coi như worker chưa nâng cấp xong → từ chối ghi, cho đọc để không chết trang)
      const authz = request.headers.get('Authorization') || '';
      const sess  = env.SESSION_SECRET ? await verifySession(authz.replace(/^Bearer\s+/i, '')) : null;
      try {
        if (request.method === 'GET') {
          if (env.SESSION_SECRET && !sess) return json({ error: 'Cần đăng nhập' }, 401);
          const g = await readGist();
          return new Response(g.body, { status: g.status, headers: { 'Content-Type':'application/json', ...CORS } });
        }
        if (request.method === 'PATCH') {
          if (!env.SESSION_SECRET)      return json({ error: 'Worker chưa cấu hình SESSION_SECRET — từ chối ghi' }, 503);
          if (!sess)                    return json({ error: 'Cần đăng nhập' }, 401);
          if (sess.role !== 'admin')    return json({ error: 'Chỉ admin được ghi' }, 403);
          const inBody = await request.text();
          const r = await fetch('https://api.github.com/gists/' + GIST_ID, {
            method: 'PATCH', headers: { ...ghHeaders, 'Content-Type': 'application/json' }, body: inBody,
          });
          return new Response(await r.text(), { status: r.status, headers: { 'Content-Type':'application/json', ...CORS } });
        }
        return json({ error: 'Method not allowed' }, 405);
      } catch (e) { return json({ error: e.message }, 502); }
    }

    // Lấy target URL từ query ?url=...
    const target = url.searchParams.get('url');
    if (!target) {
      return new Response(JSON.stringify({ error: 'Missing ?url= parameter' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
      });
    }

    // Chỉ cho phép proxy tới msu.io và maplen.gg (bảo mật)
    let targetUrl;
    try {
      targetUrl = new URL(target);
    } catch (e) {
      return new Response(JSON.stringify({ error: 'Invalid URL' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
      });
    }
    const allowed = ['msutool.com', 'msu.io', 'maplen.gg', 'msu.gg', 'maplesprout.gg', 'api.msu.gg', 'api-static.msu.io', 'gamedatahub-static.msu.io', 'api-gateway.xangle.io', 'xangle.io', 'market-static.msu.io', 'p2p.binance.com', 'pricedancing.com', 'www.pricedancing.com', 'api.avax.network', 'avax.network'];
    if (!allowed.some(d => targetUrl.hostname === d || targetUrl.hostname.endsWith('.' + d))) {
      return new Response(JSON.stringify({ error: 'Domain not allowed' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
      });
    }

    const isXangle = targetUrl.hostname.endsWith('xangle.io');
    const isP2P = targetUrl.hostname === 'p2p.binance.com';
    const isPriceDancing = targetUrl.hostname.endsWith('pricedancing.com');
    let refOrigin = 'https://msu.io';
    if (isXangle) refOrigin = 'https://msu-explorer.xangle.io';
    else if (isP2P) refOrigin = 'https://p2p.binance.com';
    else if (isPriceDancing) refOrigin = 'https://www.pricedancing.com';
    const fetchHeaders = {
      'Accept': 'application/json, text/plain, */*',
      'Accept-Language': 'en-US,en;q=0.9',
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Referer': refOrigin + '/',
      'Origin': refOrigin,
    };
    // MapleSprout (Next.js App Router): xin RSC flight payload thay vì HTML shell rỗng
    if (targetUrl.hostname.endsWith('maplesprout.gg')) {
      if (targetUrl.pathname.startsWith('/api/')) {
        fetchHeaders['Accept'] = 'application/json, text/plain, */*';
      } else {
        // Trang nhân vật: tải như trình duyệt thật (để MapleSprout render + tạo bản ghi)
        fetchHeaders['Accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8';
        fetchHeaders['Sec-Fetch-Dest'] = 'document';
        fetchHeaders['Sec-Fetch-Mode'] = 'navigate';
        fetchHeaders['Sec-Fetch-Site'] = 'none';
      }
      fetchHeaders['Referer'] = 'https://maplesprout.gg/';
      fetchHeaders['Origin'] = 'https://maplesprout.gg';
    }
    // Forward Content-Type for POST requests (needed for JSON body)
    const reqCT = request.headers.get('Content-Type');
    if (request.method === 'POST') {
      fetchHeaders['Content-Type'] = reqCT || 'application/json';
    }
    // Xangle requires these headers - forward from request if provided, else default
    if (isXangle) {
      fetchHeaders['x-chain'] = request.headers.get('x-chain') || 'NEXON';
      const sk = request.headers.get('x-secret-key');
      if (sk) fetchHeaders['x-secret-key'] = sk;
    }
    // PriceDancing API needs browser-like headers + XHR marker
    if (isPriceDancing) {
      fetchHeaders['X-Requested-With'] = 'XMLHttpRequest';
      fetchHeaders['sec-ch-ua'] = '"Chromium";v="120", "Not(A:Brand";v="24"';
      fetchHeaders['sec-ch-ua-mobile'] = '?0';
      fetchHeaders['sec-ch-ua-platform'] = '"Windows"';
      fetchHeaders['sec-fetch-dest'] = 'empty';
      fetchHeaders['sec-fetch-mode'] = 'cors';
      fetchHeaders['sec-fetch-site'] = 'same-origin';
    }
    // Binance P2P needs these to look like a real browser request
    if (isP2P) {
      fetchHeaders['clienttype'] = 'web';
      fetchHeaders['lang'] = 'en';
      fetchHeaders['sec-ch-ua'] = '"Chromium";v="120", "Not(A:Brand";v="24"';
      fetchHeaders['sec-ch-ua-mobile'] = '?0';
      fetchHeaders['sec-ch-ua-platform'] = '"Windows"';
      fetchHeaders['sec-fetch-dest'] = 'empty';
      fetchHeaders['sec-fetch-mode'] = 'cors';
      fetchHeaders['sec-fetch-site'] = 'same-origin';
    }

    try {
      const reqBody = request.method === 'POST' ? await request.clone().text() : undefined;
      // Don't edge-cache POST (different bodies); cache GET only
      // MapleSprout: KHÔNG cache (cache key theo URL nên bản HTML shell cũ sẽ bị trả lại
      // dù ta đã gửi header RSC — đây là lý do dữ liệu boss không bao giờ xuất hiện)
      const noCache = targetUrl.hostname.endsWith('maplesprout.gg');
      const cfOpt = (request.method === 'POST' || noCache) ? {} : { cacheTtl: 600, cacheEverything: true };
      let resp, body, attempt = 0;
      // Server-side retry on 429 (up to 4 times with backoff)
      while (attempt < 4) {
        resp = await fetch(target, {
          method: request.method,
          headers: fetchHeaders,
          body: reqBody,
          cf: cfOpt,
        });
        if (resp.status !== 429) break;
        attempt++;
        await new Promise(r => setTimeout(r, 400 * attempt));
      }
      // Ảnh là dữ liệu nhị phân — đọc bằng resp.text() sẽ phá hỏng file.
      // Chỉ chuyển sang text với những kiểu nội dung thực sự là chữ.
      const ctype = resp.headers.get('Content-Type') || 'application/json';
      const isText = /^(text\/|application\/(json|javascript|xml|xhtml))/i.test(ctype) || !resp.headers.get('Content-Type');
      body = isText ? await resp.text() : await resp.arrayBuffer();
      return new Response(body, {
        status: resp.status,
        headers: {
          'Content-Type': ctype,
          'Access-Control-Allow-Origin': '*',
          'Cross-Origin-Resource-Policy': 'cross-origin',
          'Cache-Control': (request.method === 'POST' || noCache) ? 'no-store' : 'public, max-age=600',
        },
      });
    } catch (e) {
      return new Response(JSON.stringify({ error: e.message }), {
        status: 502,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
      });
    }
  },
};
