// Service worker cho chế độ cài đặt (PWA).
// Nguyên tắc: LUÔN ưu tiên bản trên mạng để không bao giờ chạy bản dashboard cũ;
// bản trong cache chỉ dùng khi mất mạng.
const CACHE = 'gf-shell-v1';
const SHELL = ['./', './index.html', './manifest.webmanifest',
               './icons/icon-192.png', './icons/icon-512.png'];

self.addEventListener('install', e => {
  self.skipWaiting();
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL).catch(()=>{})));
});

self.addEventListener('activate', e => {
  e.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)));
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', e => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  // Chỉ đụng tới file của chính trang; API, proxy, Gist… để nguyên cho mạng lo
  if (url.origin !== self.location.origin) return;

  e.respondWith((async () => {
    try {
      const fresh = await fetch(req);
      if (fresh && fresh.ok) {
        const c = await caches.open(CACHE);
        c.put(req, fresh.clone());
      }
      return fresh;
    } catch (err) {
      const hit = await caches.match(req);
      if (hit) return hit;
      if (req.mode === 'navigate') {
        const idx = await caches.match('./index.html');
        if (idx) return idx;
      }
      throw err;
    }
  })());
});

// Trang gọi để nạp ngay bản mới mà không cần đóng app
self.addEventListener('message', e => { if (e.data === 'skipWaiting') self.skipWaiting(); });
