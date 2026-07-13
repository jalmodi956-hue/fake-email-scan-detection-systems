/* =========================================================
   HEXA SHIELD - AI PHISHING EMAIL DETECTOR
   FINAL SERVICE WORKER
========================================================= */

"use strict";

const CACHE_NAME = "hexa-shield-v2";

const STATIC_CACHE = [
    "/static/style.css",
    "/static/script.js"
];


/* =========================================================
   INSTALL
========================================================= */

self.addEventListener("install", (event) => {

    event.waitUntil(

        caches.open(CACHE_NAME)
            .then((cache) => {

                return cache.addAll(STATIC_CACHE);

            })
            .catch((error) => {

                console.error(
                    "Cache Install Error:",
                    error
                );

            })

    );

    self.skipWaiting();

});


/* =========================================================
   ACTIVATE
========================================================= */

self.addEventListener("activate", (event) => {

    event.waitUntil(

        caches.keys()
            .then((cacheNames) => {

                return Promise.all(

                    cacheNames.map((cacheName) => {

                        if (cacheName !== CACHE_NAME) {

                            return caches.delete(cacheName);

                        }

                        return Promise.resolve();

                    })

                );

            })

    );

    self.clients.claim();

});


/* =========================================================
   FETCH
========================================================= */

self.addEventListener("fetch", (event) => {

    const request = event.request;

    if (request.method !== "GET") {
        return;
    }

    const url = new URL(request.url);

    if (url.origin !== self.location.origin) {
        return;
    }


    /* =====================================================
       API REQUESTS - NETWORK ONLY
    ===================================================== */

    if (
        url.pathname.startsWith("/api/") ||
        url.pathname.startsWith("/scan/")
    ) {

        event.respondWith(
            fetch(request)
        );

        return;

    }


    /* =====================================================
       PAGE NAVIGATION - NETWORK FIRST
    ===================================================== */

    if (request.mode === "navigate") {

        event.respondWith(

            fetch(request)
                .catch(() => {

                    return caches.match(request);

                })

        );

        return;

    }


    /* =====================================================
       STATIC FILES - CACHE FIRST
    ===================================================== */

    if (url.pathname.startsWith("/static/")) {

        event.respondWith(

            caches.match(request)
                .then((cachedResponse) => {

                    if (cachedResponse) {

                        return cachedResponse;

                    }

                    return fetch(request)
                        .then((networkResponse) => {

                            if (
                                !networkResponse ||
                                networkResponse.status !== 200
                            ) {

                                return networkResponse;

                            }

                            const responseClone =
                                networkResponse.clone();

                            caches.open(CACHE_NAME)
                                .then((cache) => {

                                    cache.put(
                                        request,
                                        responseClone
                                    );

                                });

                            return networkResponse;

                        });

                })

        );

    }

});


/* =========================================================
   MESSAGE
========================================================= */

self.addEventListener("message", (event) => {

    if (
        event.data &&
        event.data.type === "SKIP_WAITING"
    ) {

        self.skipWaiting();

    }

});


/* =========================================================
   END SERVICE WORKER
========================================================= */