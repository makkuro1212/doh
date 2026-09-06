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
  async fetch(request, env) { 
    const url = new URL(request.url); 
    const { pathname, searchParams } = url; 
 
    if (!pathname.startsWith(env.PATH)) { 
      return new Response('not found', { status: 404 }); 
    } 
 
    const dns = searchParams.get('dns'); 
 
    if ( 
      (request.method === 'GET' && !dns) || 
      (request.method === 'POST' && 
        request.headers.get('content-type') !== 'application/dns-message') 
    ) { 
      return new Response('bad request header', { status: 400 }); 
    } 
 
    let body; 
 
    try { 
      body = request.method === 'GET' 
        ? decode(dns) 
        : new Uint8Array(await request.arrayBuffer()); 
    } catch { 
      return request.method === 'GET' 
        ? fetch(`${env.UPSTREAM}?dns=${dns}`, { headers }) 
        : new Response('invalid dns message', { status: 400 }); 
    } 
    
// 屏蔽 gdmf.apple.com
const blocked = [4,103,100,109,102,5,97,112,112,108,101,3,99,111,109,0];

let match = true;
for (let i = 0; i < blocked.length; i++) {
  if (body[i + 12] !== blocked[i]) {
    match = false;
    break;
  }
}

if (match) {
  return new Response(null, { status: 404 });
}
    
    if (body[11] === 0) { 
      body[11] = 1; 
 
      const ip = pathname.includes('edns+') 
        ? pathname.split('+').pop() 
        : request.headers.get('cf-connecting-ip'); 
 
      const extra = getAdditionalBytes(ip, ip.includes('.')); 
 
      const result = new Uint8Array(body.length + extra.length); 
      result.set(body); 
      result.set(extra, body.length); 
 
      body = result; 
    } 
 
    return fetch(env.UPSTREAM, { 
      method: 'POST', 
      headers, 
      body, 
    }); 
  }, 
};
