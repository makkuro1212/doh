const CACHE_TTL = 3600; // 1小时

const headers = {
  accept: 'application/dns-message',
  'content-type': 'application/dns-message',
};

const decode = s => {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  s += '='.repeat((4 - s.length % 4) % 4);

  const binary = atob(s);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
};

const getAdditionalBytes = (ip, ipv4) => {
  const bytes = ipv4
    ? [0, 0, 0x29, 0, 0, 0, 0, 0, 0, 0, 0x0b, 0, 8, 0, 7, 0, 1, 0x18, 0, 0, 0, 0]
    : [0, 0, 0x29, 0, 0, 0, 0, 0, 0, 0, 0x0e, 0, 8, 0, 10, 0, 2, 0x30, 0, 0, 0, 0, 0, 0, 0];

  const parts = ip.split(ipv4 ? '.' : ':');

  for (let i = 0; i < 3; i++) {
    const n = parseInt(parts[i], ipv4 ? 10 : 16);

    if (ipv4) {
      bytes[19 + i] = n;
    } else {
      bytes[19 + i * 2] = n >> 8;
      bytes[20 + i * 2] = n & 255;
    }
  }

  return bytes;
};

export default {
  async fetch(request, env, ctx) {
    const { pathname, searchParams } = new URL(request.url);

    if (!pathname.startsWith(env.PATH)) {
      return new Response('not found', { status: 404 });
    }

    const dnsValue = searchParams.get('dns');

    if (
      (request.method === 'GET' && !dnsValue) ||
      (request.method === 'POST' &&
        request.headers.get('content-type') !== 'application/dns-message')
    ) {
      return new Response('bad request header', { status: 400 });
    }

    let body;

    try {
      body =
        request.method === 'GET'
          ? decode(dnsValue)
          : new Uint8Array(await request.arrayBuffer());
    } catch {
      return fetch(`${env.UPSTREAM}?dns=${dnsValue}`, {
        method: 'GET',
        headers,
      });
    }

    // 屏蔽 gdmf.apple.com
    const blocked = [
      4, 103, 100, 109, 102,
      5, 97, 112, 112, 108, 101,
      3, 99, 111, 109,
      0,
    ];

    let match = true;

    for (let i = 0; i < blocked.length; i++) {
      if (body[i + 12] !== blocked[i]) {
        match = false;
        break;
      }
    }

    if (match) {
      const response = new Uint8Array([
        body[0], body[1],
        0x81, 0x83,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,

        // gdmf.apple.com
        0x04, 0x67, 0x64, 0x6d, 0x66,
        0x05, 0x61, 0x70, 0x70, 0x6c, 0x65,
        0x03, 0x63, 0x6f, 0x6d,
        0x00,

        // QTYPE = A
        0x00, 0x01,

        // QCLASS = IN
        0x00, 0x01,
      ]);

      return new Response(response, {
        status: 200,
        headers: {
          'content-type': 'application/dns-message',
        },
      });
    }

    if (body[11] !== 0x00) {
      return fetch(env.UPSTREAM, {
        method: 'POST',
        headers,
        body,
      });
    }

    body[11] = 0x01;

    const ip = pathname.includes('edns+')
      ? pathname.split('+').pop()
      : request.headers.get('cf-connecting-ip');

    const isIPv4 = ip.includes('.');
    const additionalBytes = getAdditionalBytes(ip, isIPv4);
    const cache = caches.default;

    const cacheKey =
      `https://dns.lan/v1/${body.subarray(2).join('')}|${additionalBytes.join('')}`;

    const cached = await cache.match(cacheKey);

    if (cached) {
      const cacheTime = Number(cached.headers.get('X-Cache-Time'));

      if (
        Number.isFinite(cacheTime) &&
        Date.now() - cacheTime < CACHE_TTL * 1000
      ) {
        const cachedBody = new Uint8Array(await cached.arrayBuffer());

        cachedBody[0] = body[0];
        cachedBody[1] = body[1];
        const responseHeaders = new Headers(cached.headers);
        responseHeaders.set('X-Cache-Hit', Date.now().toString());
        return new Response(cachedBody, {
          status: cached.status,
          statusText: cached.statusText,
          headers: responseHeaders,
        });
      }
    }

    const modifiedBody = new Uint8Array(
      body.length + additionalBytes.length
    );

    modifiedBody.set(body);
    modifiedBody.set(additionalBytes, body.length);

    const response = await fetch(env.UPSTREAM, {
      method: 'POST',
      headers,
      body: modifiedBody,
    });

    if (!response.ok) {
      return response;
    }

    const cacheHeaders = new Headers(response.headers);
    cacheHeaders.set('X-Cache-Time', Date.now().toString());
    cacheHeaders.set('Cache-Control', `public, s-maxage=${CACHE_TTL}`);
    const cacheResponse = new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: cacheHeaders,
    });

    ctx.waitUntil(cache.put(cacheKey, cacheResponse.clone()));

    return cacheResponse;
  },
};
