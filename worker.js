const CACHE_TTL_FACTOR = 2;
const MAX_CACHE_TTL = 1800;

const decoder = new TextDecoder();

const headers = {
  accept: 'application/dns-message',
  'content-type': 'application/dns-message',
};

const decodeDnsQuery = s => {
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

const readName = (body, offset) => {
  const labels = [];

  while (true) {
    const length = body[offset++];

    if (length === 0) {
      break;
    }

    if ((length & 0xc0) === 0xc0) {
      const pointer = ((length & 0x3f) << 8) | body[offset++];
      const result = readName(body, pointer);

      labels.push(result.name);

      break;
    }

    labels.push(
      decoder.decode(
        body.subarray(offset, offset + length)
      )
    );

    offset += length;
  }

  return {
    name: labels.join('.'),
    offset,
  };
};

const readQuestion = body => {
  return readName(body, 12);
};

const parseIPv4 = ip => {
  const ipParts = ip.split('.');

  return ipParts;
};

const parseIPv6 = ip => {
  const [left, right] = ip.split('::');

  const leftParts = left ? left.split(':') : [];
  const rightParts = right ? right.split(':') : [];

  return [
    ...leftParts,
    ...Array(
      8 - leftParts.length - rightParts.length
    ).fill('0'),
    ...rightParts,
  ];
};

const buildEcs = (ip, isIPv4) => {
  const additionalBytes = isIPv4
    ? [0, 0, 0x29, 0, 0, 0, 0, 0, 0, 0, 0x0b, 0, 0x08, 0, 0x07, 0, 0x01, 0x18, 0, 0, 0, 0]
    : [0, 0, 0x29, 0, 0, 0, 0, 0, 0, 0, 0x0e, 0, 0x08, 0, 0x0a, 0, 0x02, 0x30, 0, 0, 0, 0, 0, 0, 0];

  if (isIPv4) {
    const ipParts = parseIPv4(ip);

    let offset = 19;

    for (let i = 0; i < 3; i++) {
      additionalBytes[offset + i] = +ipParts[i];
    }
  } else {
    const ipParts = parseIPv6(ip);

    let offset = 19;

    for (let i = 0; i < 3; i++) {
      const hex = parseInt(ipParts[i], 16);

      additionalBytes[offset + i * 2] = hex >> 8;
      additionalBytes[offset + i * 2 + 1] = hex & 0xff;
    }
  }

  return additionalBytes;
};

const buildCacheKey = (queryBytes, additionalBytes) => {
  return (
    `https://dns.lan/v3/` +
    `${encodeBase64Url(queryBytes)}/` +
    `${encodeBase64Url(additionalBytes)}`
  );
};

const getDnsTtl = response => {
  const cacheControl = response.headers.get('cache-control');

  if (!cacheControl) {
    return null;
  }

  const sMaxAge = cacheControl.match(
    /(?:^|,)\s*s-maxage=(\d+)/i
  );

  if (sMaxAge) {
    return Number(sMaxAge[1]);
  }

  const maxAge = cacheControl.match(
    /(?:^|,)\s*max-age=(\d+)/i
  );

  if (maxAge) {
    return Number(maxAge[1]);
  }

  return null;
};

const makeNxDomain = body => {
  const responseBody = new Uint8Array([
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

  responseBody[0] = body[0];
  responseBody[1] = body[1];

  return new Response(responseBody, {
    status: 200,
    headers: {
      'content-type': 'application/dns-message',
    },
  });
};

const normalizeResponse = (response, cacheTtl) => {
  const cacheHeaders = new Headers({
    'content-type': 'application/dns-message',
    'cache-control': `s-maxage=${cacheTtl}`,
  });

  return new Response(
    response.body,
    {
      status: response.status,
      statusText: response.statusText,
      headers: cacheHeaders,
    }
  );
};

const validateDnsPacket = body => {
  return body;
};

export default {
  async fetch(request, env, ctx) {
    // 1. validate HTTP
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

    // 2. decode DNS
    let body;

    try {
      body = request.method === 'GET'
        ? decodeDnsQuery(dnsValue)
        : new Uint8Array(await request.arrayBuffer());
    } catch {
      return new Response('bad dns message', {
        status: 400
      });
    }

    // 3. validate DNS packet
    body = validateDnsPacket(body);

    // 4. parse question
    const { name } = readQuestion(body);

    // 5. special domain
    if (name.toLowerCase() === 'gdmf.apple.com') {
      return makeNxDomain(body);
    }

    // 6. ECS
    const ARCOUNT = body[10] << 8 | body[11];

    if (ARCOUNT !== 0) {
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
    const additionalBytes = buildEcs(ip, isIPv4);

    const queryBytes = body.subarray(2);

    // 7. cache lookup
    const cacheKey = buildCacheKey(
      queryBytes,
      additionalBytes
    );

    const cache = caches.default;
    const cached = await cache.match(cacheKey);

    if (cached) {
      const cachedBody = new Uint8Array(
        await cached.arrayBuffer()
      );

      cachedBody[0] = body[0];
      cachedBody[1] = body[1];

      return new Response(cachedBody, {
        status: cached.status,
        statusText: cached.statusText,
        headers: cached.headers,
      });
    }

    // 8. upstream
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

    // 9. DNS TTL
    const upstreamTtl = getDnsTtl(response);

    const cacheTtl = upstreamTtl === null
      ? MAX_CACHE_TTL
      : Math.min(
          upstreamTtl * CACHE_TTL_FACTOR,
          MAX_CACHE_TTL
        );

    // 10. cache
    const cacheResponse = normalizeResponse(
      response,
      cacheTtl
    );

    ctx.waitUntil(
      cache.put(cacheKey, cacheResponse.clone())
    );

    // 11. response
    return cacheResponse;
  },
};
