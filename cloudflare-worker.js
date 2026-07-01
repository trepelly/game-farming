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

    // ══════════════ GIST ROUTES (token giấu trong env.GIST_TOKEN) ══════════════
    // GET  /gist        → đọc toàn bộ Gist (trả files)
    // PATCH /gist       → ghi Gist (body = {files:{...}})
    if (url.pathname === '/gist') {
      const GIST_ID = env.GIST_ID || 'fbbc7f578f4ad7760206f397c0706348';
      const token   = env.GIST_TOKEN;
      if (!token) {
        return new Response(JSON.stringify({ error: 'GIST_TOKEN chưa được cấu hình trong Worker' }), {
          status: 500, headers: { 'Content-Type': 'application/json', ...CORS },
        });
      }
      const ghHeaders = {
        'Authorization': 'token ' + token,
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'msu-proxy',
      };
      try {
        if (request.method === 'GET') {
          const r = await fetch('https://api.github.com/gists/' + GIST_ID, { headers: ghHeaders });
          const body = await r.text();
          return new Response(body, { status: r.status, headers: { 'Content-Type': 'application/json', ...CORS } });
        }
        if (request.method === 'PATCH') {
          const inBody = await request.text();
          const r = await fetch('https://api.github.com/gists/' + GIST_ID, {
            method: 'PATCH',
            headers: { ...ghHeaders, 'Content-Type': 'application/json' },
            body: inBody,
          });
          const body = await r.text();
          return new Response(body, { status: r.status, headers: { 'Content-Type': 'application/json', ...CORS } });
        }
        return new Response(JSON.stringify({ error: 'Method not allowed' }), { status: 405, headers: { 'Content-Type': 'application/json', ...CORS } });
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), { status: 502, headers: { 'Content-Type': 'application/json', ...CORS } });
      }
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
    const allowed = ['msu.io', 'maplen.gg', 'api-static.msu.io', 'gamedatahub-static.msu.io', 'api-gateway.xangle.io', 'xangle.io', 'market-static.msu.io', 'p2p.binance.com', 'pricedancing.com', 'www.pricedancing.com'];
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
      const cfOpt = request.method === 'POST' ? {} : { cacheTtl: 600, cacheEverything: true };
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
      body = await resp.text();
      return new Response(body, {
        status: resp.status,
        headers: {
          'Content-Type': resp.headers.get('Content-Type') || 'application/json',
          'Access-Control-Allow-Origin': '*',
          'Cache-Control': request.method === 'POST' ? 'no-store' : 'public, max-age=600',
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
