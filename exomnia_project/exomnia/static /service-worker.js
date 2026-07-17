// Exomnia PWA service worker
// Strategy: cache-first ONLY for static, versioned assets (icons/manifest).
// Everything else (HTML pages, /api/*, socket.io) always goes to the
// network untouched — this is a live chat app, so we never want to risk
// showing a stale page or stale message data from a cache.

const CACHE_NAME = 'exomnia-static-v1';
const STATIC_ASSETS = [
  '/static/manifest.json',
  '/static/icons/icon-192.png',
  '/static/icons/icon-512.png',
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(STATIC_ASSETS))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(names =>
      Promise.all(
        names.filter(name => name !== CACHE_NAME)
             .map(name => caches.delete(name))
      )
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);

  // Only handle our own static assets folder; let the browser handle
  // everything else (pages, /api/, /socket.io/, /uploads/, etc.) normally.
  if (event.request.method === 'GET' && url.pathname.startsWith('/static/')) {
    event.respondWith(
      caches.match(event.request).then(cached => {
        if (cached) return cached;
        return fetch(event.request).then(response => {
          // Cache a copy for next time
          const copy = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(event.request, copy));
          return response;
        });
      })
    );
  }
  // No event.respondWith() call for anything else = default network behavior.
});
