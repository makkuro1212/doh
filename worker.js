const headers = {
  accept: 'application/dns-message',
  'content-type': 'application/dns-message',
  };
  
const base64UrlReplace = (input) => input.replace(/[-_\s]/g, c => (c === '-' ? '+' : c === '_' ? '/' : ''));
  
const decodeBase64UrlToUint8Array = (input) =>
  new Uint8Array(
    atob(base64UrlReplace(input))
      .split('')
      .map(c => c.charCodeAt(0))
  );
  
  // const decodeBase64UrlToString = (input) => atob(base64UrlReplace(input));
  
const getAdditionalBytes = (ip, isIPv4) => {
  const additionalBytes = isIPv4
    ? [0, 0, 0x29, 0, 0, 0, 0, 0, 0, 0, 0x0b, 0, 0x08, 0, 0x07, 0, 0x01, 0x18, 0, 0, 0, 0]
    : [0, 0, 0x29, 0, 0, 0, 0, 0, 0, 0, 0x0e, 0, 0x08, 0, 0x0a, 0, 0x02, 0x30, 0, 0, 0, 0, 0, 0, 0];
  if (isIPv4) {
    const ipParts = ip.split('.')
    let offset = 19
    for (let i = 0;i < 3;i++){
      additionalBytes[offset+i] = +ipParts[i]
    }
  }else {
    const ipParts = ip.split(':')
    let offset = 19
    for (let i = 0;i < 3;i++){
      const hex = parseInt(ipParts[i], 16);
      additionalBytes[offset+i*2] = hex >> 8
      additionalBytes[offset+i*2+1] = hex & 0xff
    }
  }
  return additionalBytes;
};
  
export default {
  async fetch(request, env, ctx) {
    const { pathname, searchParams } = new URL(request.url);
  
    if (!pathname.includes(env.PATH)) return new Response('not found', { status: 404 });
    
    const dnsValue = searchParams.get('dns');
    if (
      (request.method === 'GET' && !dnsValue) ||
      (request.method === 'POST' && request.headers.get('content-type') !== 'application/dns-message')
    )
      return new Response('bad request header', { status: 400 });
  
    let body;
    try {
      body =
        request.method === 'GET'
          ? decodeBase64UrlToUint8Array(dnsValue)
          : new Uint8Array(await request.arrayBuffer());
    } catch {
      return fetch(`${env.UPSTREAM}?dns=${dnsValue}`, { method: 'GET', headers });
    }
  
    if (body[11] === 0x00) {
      body[11] = 0x01;
      let ip = pathname.includes('edns+')
      ? pathname.split('+').pop()
      : request.headers.get('cf-connecting-ip')
      const isIPv4 = ip.includes('.');
      const additionalBytes = getAdditionalBytes(ip, isIPv4);
      const cache = caches.default;
      const cacheKey = `https://dns.lan/${body.slice(2).join('')}${additionalBytes.join('')}`;
      const cached = await cache.match(cacheKey);
      if (cached) return cached;
  
      const modifiedBody = new Uint8Array(body.length + additionalBytes.length);
      modifiedBody.set(body);
      modifiedBody.set(additionalBytes, body.length);
  
      let response = await fetch(env.UPSTREAM, {
        method: 'POST',
        headers,
        body: modifiedBody,
      });
      if (response.ok) {
        const respHeaders = new Headers({
          'Cache-Control': 's-maxage=25200',
          'Content-Type': 'application/dns-message',
        });
        response = new Response(response.body, {
          status: response.status,
          statusText: response.statusText,
          headers: respHeaders,
        });
        ctx.waitUntil(cache.put(cacheKey, response.clone()));
      }
      return response;
    }
  
    return fetch(env.UPSTREAM, { method: 'POST', headers, body });
  },
};