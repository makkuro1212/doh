const CACHE_TTL = 3600;

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

const encodeBase64Url = bytes => {
  const chars =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

  let output = '';
  let i = 0;

  for (; i + 2 < bytes.length; i += 3) {
    const a = bytes[i];
    const b = bytes[i + 1];
    const c = bytes[i + 2];

    output +=
      chars[a >> 2] +
      chars[((a & 3) << 4) | (b >> 4)] +
      chars[((b & 15) << 2) | (c >> 6)] +
      chars[c & 63];
  }

  const remaining = bytes.length - i;

  if (remaining === 1) {
    const a = bytes[i];

    output +=
      chars[a >> 2] +
      chars[(a & 3) << 4];
  } else if (remaining === 2) {
    const a = bytes[i];
    const b = bytes[i + 1];

    output +=
      chars[a >> 2] +
      chars[((a & 3) << 4) | (b >> 4)] +
      chars[(b & 15) << 2];
  }

  return output;
};

const getAdditionalBytes = (ip, ipv4) => {
  const bytes = new Uint8Array(
    ipv4
      ? [
          0, 0, 0x29, 0, 0, 0, 0, 0, 0, 0,
          0x0b, 0, 8, 0, 7, 0, 1, 0x18, 0, 0, 0, 0,
        ]
      : [
          0, 0, 0x29, 0, 0, 0, 0, 0, 0, 0,
          0x0e, 0, 8, 0, 10, 0, 2, 0x30, 0, 0, 0, 0, 0, 0, 0,
        ]
  );

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

const GDMF_NXDOMAIN = new Uint8Array([
  0, 0,
  0x81, 0x83,
  0x00, 0x01,
  0x00, 0x00,
  0x00, 0x00,
  0x00, 0x00,
  0x04, 0x67, 0x64, 0x6d, 0x66,
  0x05, 0x61, 0x70, 0x70, 0x6c, 0x65,
  0x03, 0x63, 0x6f, 0x6d,
  0x00,
  0x00, 0x01,
  0x00, 0x01,
]);

export default {
  async fetch(request, env, ctx) {
    const { pathname, searchParams } = new URL(request.url);

    if (!pathname.startsWith(env.PATH)) {
      return new Response('not found', { status: 404 });
    }

    const dnsValue = searchParams.get('dns');

    if (
      (request.method === 'GET' && !dnsValue) ||
      (
        request.method === 'POST' &&
        request.headers.get('content-type') !== 'application/dns-message'
      )
    ) {
      return new Response('bad request header', { status: 400 });
    }

    let body;

    try {
      body = request.method === 'GET'
        ? decode(dnsValue)
        : new Uint8Array(await request.arrayBuffer());
    } catch {
      return fetch(`${env.UPSTREAM}?dns=${dnsValue}`, {
        method: 'GET',
        headers,
      });
    }

    if (
      body[12] === 4 && body[13] === 103 &&
      body[14] === 100 && body[15] === 109 &&
      body[16] === 102 && body[17] === 5 &&
      body[18] === 97 && body[19] === 112 &&
      body[20] === 112 && body[21] === 108 &&
      body[22] === 101 && body[23] === 3 &&
      body[24] === 99 && body[25] === 111 &&
      body[26] === 109 && body[27] === 0
    ) {
      const responseBody = new Uint8Array(GDMF_NXDOMAIN);

      responseBody[0] = body[0];
      responseBody[1] = body[1];

      return new Response(responseBody, {
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

    let ip;

    const plusIndex = pathname.lastIndexOf('+');

    if (plusIndex !== -1) {
      ip = pathname.slice(plusIndex + 1);
    } else {
      ip = request.headers.get('cf-connecting-ip');
    }

    const isIPv4 = ip.includes('.');
    const additionalBytes = getAdditionalBytes(ip, isIPv4);

    const queryBytes = body.subarray(2);

    const cacheKey =
      `https://dns.lan/v1/${encodeBase64Url(queryBytes)}.${encodeBase64Url(additionalBytes)}`;

    const cache = caches.default;
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

        return new Response(cachedBody, {
          status: cached.status,
          statusText: cached.statusText,
          headers: cached.headers,
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

    cacheHeaders.set(
      'Cache-Control',
      `public, s-maxage=${CACHE_TTL}`
    );

    cacheHeaders.set(
      'X-Cache-Time',
      Date.now().toString()
    );

    const cacheResponse = new Response(
      response.body,
      {
        status: response.status,
        statusText: response.statusText,
        headers: cacheHeaders,
      }
    );

    ctx.waitUntil(
      cache.put(cacheKey, cacheResponse.clone())
    );

    return cacheResponse;
  },
};
