// MSU Proxy - Cloudflare Worker
// Cho phép fetch msu.io API từ browser (bỏ qua CORS)

export default {
  async fetch(request) {
    const url = new URL(request.url);

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': '*',
        },
      });
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
    const allowed = ['msu.io', 'maplen.gg', 'api-static.msu.io', 'gamedatahub-static.msu.io'];
    if (!allowed.some(d => targetUrl.hostname === d || targetUrl.hostname.endsWith('.' + d))) {
      return new Response(JSON.stringify({ error: 'Domain not allowed' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
      });
    }

    const fetchHeaders = {
      'Accept': 'application/json, text/plain, */*',
      'Accept-Language': 'en-US,en;q=0.9',
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Referer': 'https://msu.io/',
      'Origin': 'https://msu.io',
    };

    try {
      let resp, body, attempt = 0;
      // Server-side retry on 429 (up to 4 times with backoff)
      while (attempt < 4) {
        resp = await fetch(target, {
          method: request.method,
          headers: fetchHeaders,
          body: request.method === 'POST' ? await request.clone().text() : undefined,
          cf: { cacheTtl: 600, cacheEverything: true },
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
          'Cache-Control': 'public, max-age=600',
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
