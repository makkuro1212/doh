const DNS_HEADERS = {
  accept: 'application/dns-message',
  'content-type': 'application/dns-message',
};

// 最大缓存时间：7 小时
const MAX_CACHE_TTL = 25200;

// DNS Header 固定长度
const DNS_HEADER_SIZE = 12;


/* =========================================================
 * Base64URL → Uint8Array
 * ======================================================= */

function decodeBase64Url(input) {
  input = input.replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, '');

  const mod = input.length & 3;

  // Base64 长度 mod 4 == 1 一定非法
  if (mod === 1) {
    throw new Error('invalid base64url');
  }

  if (mod) {
    input += '='.repeat(4 - mod);
  }

  const decoded = atob(input);
  const output = new Uint8Array(decoded.length);

  for (let i = 0; i < decoded.length; i++) {
    output[i] = decoded.charCodeAt(i);
  }

  return output;
}


/* =========================================================
 * IPv4
 * ======================================================= */

function parseIPv4(ip) {
  const result = new Uint8Array(4);

  let start = 0;

  for (let i = 0; i < 4; i++) {
    const end = i === 3 ? ip.length : ip.indexOf('.', start);

    if (end < 0) {
      return null;
    }

    const part = ip.slice(start, end);

    if (
      part.length === 0 ||
      part.length > 3
    ) {
      return null;
    }

    const value = Number(part);

    if (
      !Number.isInteger(value) ||
      value < 0 ||
      value > 255
    ) {
      return null;
    }

    result[i] = value;
    start = end + 1;
  }

  if (start !== ip.length + 1) {
    return null;
  }

  return result;
}


/* =========================================================
 * IPv6
 *
 * 支持：
 *
 * 2001:db8::1
 * ::1
 * 2001:db8:0:0:0:0:0:1
 * ::ffff:192.0.2.1
 * ======================================================= */

function parseIPv6(ip) {
  // IPv4 embedded IPv6
  if (ip.includes('.')) {
    const colon = ip.lastIndexOf(':');

    if (colon < 0) {
      return null;
    }

    const ipv4 = parseIPv4(ip.slice(colon + 1));

    if (!ipv4) {
      return null;
    }

    const a = ((ipv4[0] << 8) | ipv4[1]).toString(16);
    const b = ((ipv4[2] << 8) | ipv4[3]).toString(16);

    ip = ip.slice(0, colon + 1) + a + ':' + b;
  }

  const doubleColon = ip.indexOf('::');

  let groups;

  if (doubleColon >= 0) {
    // 只能出现一个 ::
    if (ip.indexOf('::', doubleColon + 2) >= 0) {
      return null;
    }

    const left = ip.slice(0, doubleColon);
    const right = ip.slice(doubleColon + 2);

    const leftGroups = left ? left.split(':') : [];
    const rightGroups = right ? right.split(':') : [];

    if (
      leftGroups.length +
      rightGroups.length >= 8
    ) {
      return null;
    }

    const zeroCount =
      8 -
      leftGroups.length -
      rightGroups.length;

    groups = [
      ...leftGroups,
      ...new Array(zeroCount).fill('0'),
      ...rightGroups,
    ];
  } else {
    groups = ip.split(':');

    if (groups.length !== 8) {
      return null;
    }
  }

  if (groups.length !== 8) {
    return null;
  }

  const output = new Uint8Array(16);

  for (let i = 0; i < 8; i++) {
    const group = groups[i];

    if (
      group.length === 0 ||
      group.length > 4 ||
      !/^[0-9a-fA-F]+$/.test(group)
    ) {
      return null;
    }

    const value = parseInt(group, 16);

    if (value > 0xffff) {
      return null;
    }

    output[i * 2] = value >>> 8;
    output[i * 2 + 1] = value & 0xff;
  }

  return output;
}


/* =========================================================
 * ECS Prefix
 *
 * IPv4 → /24
 * IPv6 → /48
 *
 * 注意：
 *
 * Cache 使用的是 ECS Prefix，而不是完整 IP。
 *
 * 例如：
 *
 * 1.2.3.1
 * 1.2.3.2
 * 1.2.3.200
 *
 * 全部：
 *
 * 1.2.3.0/24
 *
 * 因此可以共享 DNS Cache。
 * ======================================================= */

function getClientNetwork(ip) {
  const ipv4 = parseIPv4(ip);

  if (ipv4) {
    return {
      family: 1,
      prefixLength: 24,
      bytes: ipv4,
      cacheKey:
        `${ipv4[0]}.${ipv4[1]}.${ipv4[2]}.0/24`,
    };
  }

  const ipv6 = parseIPv6(ip);

  if (ipv6) {
    // 前 48 bit
    return {
      family: 2,
      prefixLength: 48,
      bytes: ipv6,
      cacheKey:
        `${ipv6[0].toString(16)}:${ipv6[1].toString(16)}:${ipv6[2].toString(16)}::/48`,
    };
  }

  return null;
}


/* =========================================================
 * DNS Name Parser
 *
 * 用于安全跳过 QNAME / RR NAME。
 * 支持 DNS compression pointer。
 * ======================================================= */

function skipDnsName(packet, offset) {
  const length = packet.length;

  if (offset >= length) {
    return -1;
  }

  let pos = offset;
  let jumps = 0;

  while (pos < length) {
    const len = packet[pos];

    // compression pointer
    if ((len & 0xc0) === 0xc0) {
      if (pos + 1 >= length) {
        return -1;
      }

      return pos + 2;
    }

    // 非法 label
    if (len & 0xc0) {
      return -1;
    }

    // root
    if (len === 0) {
      return pos + 1;
    }

    pos += len + 1;

    if (pos > length) {
      return -1;
    }

    // 防止恶意超长循环
    if (++jumps > 128) {
      return -1;
    }
  }

  return -1;
}


/* =========================================================
 * 查找 OPT RR
 *
 * 返回：
 *
 * {
 *   start,
 *   end,
 *   rdataStart,
 *   rdataEnd,
 *   ttlOffset
 * }
 *
 * 如果没有 OPT，返回 null。
 * ======================================================= */

function findOptRecord(packet) {
  if (packet.length < DNS_HEADER_SIZE) {
    return null;
  }

  const qdCount =
    (packet[4] << 8) |
    packet[5];

  const anCount =
    (packet[6] << 8) |
    packet[7];

  const nsCount =
    (packet[8] << 8) |
    packet[9];

  const arCount =
    (packet[10] << 8) |
    packet[11];

  let offset = DNS_HEADER_SIZE;

  // Questions
  for (let i = 0; i < qdCount; i++) {
    offset = skipDnsName(packet, offset);

    if (offset < 0 || offset + 4 > packet.length) {
      return null;
    }

    offset += 4;
  }

  // Answers + Authority + Additional
  const totalRR =
    anCount +
    nsCount +
    arCount;

  for (let i = 0; i < totalRR; i++) {
    const rrStart = offset;

    offset = skipDnsName(packet, offset);

    if (offset < 0 || offset + 10 > packet.length) {
      return null;
    }

    const type =
      (packet[offset] << 8) |
      packet[offset + 1];

    const ttlOffset = offset + 4;

    const rdLength =
      (packet[offset + 8] << 8) |
      packet[offset + 9];

    const rdataStart = offset + 10;
    const rdataEnd = rdataStart + rdLength;

    if (rdataEnd > packet.length) {
      return null;
    }

    // OPT TYPE = 41
    if (type === 41) {
      return {
        start: rrStart,
        end: rdataEnd,
        rdataStart,
        rdataEnd,
        ttlOffset,
      };
    }

    offset = rdataEnd;
  }

  return null;
}


/* =========================================================
 * 创建 ECS Option
 *
 * IPv4:
 *
 * OPTION CODE = 8
 * FAMILY      = 1
 * PREFIX      = 24
 * SCOPE       = 0
 * ADDRESS     = 3 bytes
 *
 * IPv6:
 *
 * OPTION CODE = 8
 * FAMILY      = 2
 * PREFIX      = 48
 * SCOPE       = 0
 * ADDRESS     = 6 bytes
 * ======================================================= */

function createEcsOption(network) {
  const addressLength =
    network.family === 1 ? 3 : 6;

  const optionLength =
    4 + addressLength;

  const output =
    new Uint8Array(4 + optionLength);

  // OPTION CODE = 8
  output[0] = 0;
  output[1] = 8;

  // OPTION LENGTH
  output[2] = optionLength >>> 8;
  output[3] = optionLength & 0xff;

  // FAMILY
  output[4] = network.family >>> 8;
  output[5] = network.family & 0xff;

  // SOURCE PREFIX
  output[6] = network.prefixLength;

  // SCOPE PREFIX
  output[7] = 0;

  // Address
  for (let i = 0; i < addressLength; i++) {
    output[8 + i] = network.bytes[i];
  }

  return output;
}


/* =========================================================
 * 在已有 OPT 中设置 ECS
 *
 * 如果原 DNS Query 已经有 ECS：
 *
 * → 删除旧 ECS
 * → 写入当前客户端 ECS
 *
 * 如果有其他 EDNS option：
 *
 * → 保留
 *
 * 如果没有 OPT：
 *
 * → 创建新的 OPT
 * ======================================================= */

function addOrReplaceEcs(packet, network) {
  const opt = findOptRecord(packet);

  const ecs = createEcsOption(network);

  if (!opt) {
    return appendNewOpt(packet, ecs);
  }

  const oldRdata =
    packet.slice(
      opt.rdataStart,
      opt.rdataEnd
    );

  const kept = [];

  let pos = 0;

  while (pos + 4 <= oldRdata.length) {
    const code =
      (oldRdata[pos] << 8) |
      oldRdata[pos + 1];

    const len =
      (oldRdata[pos + 2] << 8) |
      oldRdata[pos + 3];

    const end =
      pos + 4 + len;

    if (end > oldRdata.length) {
      // malformed EDNS option
      return null;
    }

    // ECS = 8
    if (code !== 8) {
      kept.push(
        oldRdata.slice(pos, end)
      );
    }

    pos = end;
  }

  if (pos !== oldRdata.length) {
    return null;
  }

  let newRdataLength = ecs.length;

  for (const item of kept) {
    newRdataLength += item.length;
  }

  if (newRdataLength > 0xffff) {
    return null;
  }

  const oldRdataLength =
    opt.rdataEnd -
    opt.rdataStart;

  const delta =
    newRdataLength -
    oldRdataLength;

  const output =
    new Uint8Array(
      packet.length + delta
    );

  // OPT 前面的部分
  output.set(
    packet.subarray(0, opt.rdataStart),
    0
  );

  let write = opt.rdataStart;

  // 保留其他 EDNS options
  for (const item of kept) {
    output.set(item, write);
    write += item.length;
  }

  // 写入新的 ECS
  output.set(ecs, write);
  write += ecs.length;

  // OPT 后面的部分
  output.set(
    packet.subarray(opt.rdataEnd),
    write
  );

  // 修改 RDLENGTH
  const rdLengthOffset =
    opt.rdataStart - 2;

  output[rdLengthOffset] =
    newRdataLength >>> 8;

  output[rdLengthOffset + 1] =
    newRdataLength & 0xff;

  return output;
}


/* =========================================================
 * 没有 OPT 时创建新的 OPT RR
 * ======================================================= */

function appendNewOpt(packet, ecs) {
  const arCount =
    (packet[10] << 8) |
    packet[11];

  if (arCount === 0xffff) {
    return null;
  }

  /*
   * OPT:
   *
   * NAME      1
   * TYPE      2
   * CLASS     2
   * TTL       4
   * RDLENGTH  2
   * RDATA     ECS
   */

  const optLength =
    11 + ecs.length;

  const opt =
    new Uint8Array(optLength);

  let p = 0;

  // NAME
  opt[p++] = 0;

  // TYPE = OPT (41)
  opt[p++] = 0;
  opt[p++] = 41;

  // UDP payload size = 1232
  //
  // 1232 是现代 DNS over UDP 常用的安全值。
  opt[p++] = 4;
  opt[p++] = 208;

  // Extended RCODE + Version + Flags
  opt[p++] = 0;
  opt[p++] = 0;
  opt[p++] = 0;
  opt[p++] = 0;

  // RDLENGTH
  opt[p++] =
    ecs.length >>> 8;

  opt[p++] =
    ecs.length & 0xff;

  opt.set(ecs, p);

  const output =
    new Uint8Array(
      packet.length + opt.length
    );

  output.set(packet);

  output.set(
    opt,
    packet.length
  );

  // ARCOUNT + 1
  output[10] =
    (arCount + 1) >>> 8;

  output[11] =
    (arCount + 1) & 0xff;

  return output;
}


/* =========================================================
 * Cache Key
 *
 * 重要：
 *
 * Transaction ID 不参与 Cache Key。
 *
 * Cache Key =
 *
 *   ECS Prefix
 *   +
 *   DNS Query（去掉 Transaction ID）
 *
 * 例如：
 *
 * 1.2.3.1
 * 1.2.3.200
 *
 * 都会命中：
 *
 * /1.2.3.0/24/<query>
 * ======================================================= */

function makeCacheKey(packet, network) {
  const query =
    packet.subarray(2);

  let binary = '';

  // 去掉 Transaction ID
  for (let i = 0; i < query.length; i++) {
    binary += String.fromCharCode(
      query[i]
    );
  }

  const encoded =
    btoa(binary)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');

  return new Request(
    `https://dns-cache.invalid/v1/${network.cacheKey}/${encoded}`,
    {
      method: 'GET',
    }
  );
}


/* =========================================================
 * 从 DNS Response 中计算 TTL
 *
 * 忽略：
 *
 * - OPT RR
 *
 * 使用所有普通 RR 中的最小 TTL。
 *
 * 最终：
 *
 * min(DNS TTL, MAX_CACHE_TTL)
 *
 * ======================================================= */

function getResponseTTL(packet) {
  if (packet.length < DNS_HEADER_SIZE) {
    return 0;
  }

  const flags =
    (packet[2] << 8) |
    packet[3];

  // 必须是 response
  if (!(flags & 0x8000)) {
    return 0;
  }

  // RCODE
  const rcode =
    flags & 0x000f;

  // SERVFAIL / REFUSED 等不要缓存
  if (
    rcode === 2 ||
    rcode === 5
  ) {
    return 0;
  }

  const qdCount =
    (packet[4] << 8) |
    packet[5];

  const anCount =
    (packet[6] << 8) |
    packet[7];

  const nsCount =
    (packet[8] << 8) |
    packet[9];

  const arCount =
    (packet[10] << 8) |
    packet[11];

  let offset = DNS_HEADER_SIZE;

  // Questions
  for (let i = 0; i < qdCount; i++) {
    offset = skipDnsName(packet, offset);

    if (
      offset < 0 ||
      offset + 4 > packet.length
    ) {
      return 0;
    }

    offset += 4;
  }

  let minTTL = Infinity;

  const totalRR =
    anCount +
    nsCount +
    arCount;

  for (let i = 0; i < totalRR; i++) {
    offset = skipDnsName(packet, offset);

    if (
      offset < 0 ||
      offset + 10 > packet.length
    ) {
      return 0;
    }

    const type =
      (packet[offset] << 8) |
      packet[offset + 1];

    const ttl =
      (
        packet[offset + 4] * 0x1000000 +
        packet[offset + 5] * 0x10000 +
        packet[offset + 6] * 0x100 +
        packet[offset + 7]
      ) >>> 0;

    const rdLength =
      (packet[offset + 8] << 8) |
      packet[offset + 9];

    const rdataStart =
      offset + 10;

    const rdataEnd =
      rdataStart + rdLength;

    if (rdataEnd > packet.length) {
      return 0;
    }

    // OPT TTL 不是普通 DNS TTL
    if (type !== 41) {
      if (ttl < minTTL) {
        minTTL = ttl;
      }
    }

    offset = rdataEnd;
  }

  if (minTTL === Infinity) {
    return 0;
  }

  return Math.min(
    minTTL,
    MAX_CACHE_TTL
  );
}


/* =========================================================
 * 修改 DNS Response Transaction ID
 *
 * 这是缓存 DNS 时非常重要的一步。
 *
 * Cache Key 不包含 Transaction ID，
 * 因此缓存 Response 里的 ID 可能来自上一个客户端。
 *
 * 必须替换成当前请求的 ID。
 * ======================================================= */

function restoreTransactionId(
  response,
  request
) {
  if (
    response.length < 2 ||
    request.length < 2
  ) {
    return response;
  }

  // 如果 ID 已经一致，避免复制整个 packet
  if (
    response[0] === request[0] &&
    response[1] === request[1]
  ) {
    return response;
  }

  const output =
    new Uint8Array(response);

  output[0] = request[0];
  output[1] = request[1];

  return output;
}


/* =========================================================
 * 创建 Response
 * ======================================================= */

function createDnsResponse(
  body,
  ttl
) {
  const headers =
    new Headers();

  headers.set(
    'Content-Type',
    'application/dns-message'
  );

  if (ttl > 0) {
    headers.set(
      'Cache-Control',
      `public, s-maxage=${ttl}`
    );
  } else {
    headers.set(
      'Cache-Control',
      'no-store'
    );
  }

  return new Response(
    body,
    {
      status: 200,
      headers,
    }
  );
}


/* =========================================================
 * Worker
 * ======================================================= */

export default {
  async fetch(request, env, ctx) {
    const url =
      new URL(request.url);

    const pathname =
      url.pathname;

    /*
     * 建议这里改成：
     *
     * pathname.startsWith(env.PATH)
     *
     * 而不是 includes()
     *
     * 防止类似：
     *
     * /abc/your-path-attack
     *
     * 被误判。
     */
    if (
      !pathname.startsWith(env.PATH)
    ) {
      return new Response(
        'not found',
        {
          status: 404,
        }
      );
    }


    /* -----------------------------------------------------
     * Method
     * --------------------------------------------------- */

    const method =
      request.method;

    if (
      method !== 'GET' &&
      method !== 'POST'
    ) {
      return new Response(
        'method not allowed',
        {
          status: 405,
          headers: {
            Allow: 'GET, POST',
          },
        }
      );
    }


    /* -----------------------------------------------------
     * Read DNS Query
     * --------------------------------------------------- */

    let query;

    if (method === 'GET') {
      const dns =
        url.searchParams.get('dns');

      if (!dns) {
        return new Response(
          'missing dns parameter',
          {
            status: 400,
          }
        );
      }

      try {
        query =
          decodeBase64Url(dns);
      } catch {
        return new Response(
          'invalid dns parameter',
          {
            status: 400,
          }
        );
      }
    } else {
      const contentType =
        request.headers.get(
          'content-type'
        ) || '';

      const mediaType =
        contentType
          .split(';', 1)[0]
          .trim()
          .toLowerCase();

      if (
        mediaType !==
        'application/dns-message'
      ) {
        return new Response(
          'invalid content-type',
          {
            status: 400,
          }
        );
      }

      try {
        query =
          new Uint8Array(
            await request.arrayBuffer()
          );
      } catch {
        return new Response(
          'invalid request body',
          {
            status: 400,
          }
        );
      }
    }


    /* -----------------------------------------------------
     * Basic DNS validation
     * --------------------------------------------------- */

    if (
      query.length < DNS_HEADER_SIZE
    ) {
      return new Response(
        'invalid dns message',
        {
          status: 400,
        }
      );
    }

    const flags =
      (query[2] << 8) |
      query[3];

    // QR=1：已经是 response
    if (flags & 0x8000) {
      return new Response(
        'dns query required',
        {
          status: 400,
        }
      );
    }


    /* -----------------------------------------------------
     * Client IP
     *
     * edns+IP 优先
     * 否则 CF-Connecting-IP
     * --------------------------------------------------- */

    let clientIP;

    if (
      pathname.includes('edns+')
    ) {
      const plus =
        pathname.lastIndexOf('+');

      clientIP =
        pathname.slice(plus + 1);
    } else {
      clientIP =
        request.headers.get(
          'CF-Connecting-IP'
        );
    }

    if (!clientIP) {
      return new Response(
        'client ip unavailable',
        {
          status: 400,
        }
      );
    }


    /* -----------------------------------------------------
     * ECS Network
     * --------------------------------------------------- */

    const network =
      getClientNetwork(clientIP);

    if (!network) {
      return new Response(
        'invalid client ip',
        {
          status: 400,
        }
      );
    }


    /* -----------------------------------------------------
     * Cache lookup
     *
     * 注意：
     *
     * Cache key 使用 ECS Prefix，
     * 不是完整 IP。
     *
     * 所以同一 /24 或 /48 可以共享。
     * --------------------------------------------------- */

    const cache =
      caches.default;

    const cacheKey =
      makeCacheKey(
        query,
        network
      );

    const cached =
      await cache.match(
        cacheKey
      );

    if (cached) {
      /*
       * 必须修复 Transaction ID。
       *
       * 缓存 Response 里的 ID
       * 不一定属于当前请求。
       */
      const cachedBody =
        new Uint8Array(
          await cached.arrayBuffer()
        );

      const fixedBody =
        restoreTransactionId(
          cachedBody,
          query
        );

      return new Response(
        fixedBody,
        {
          status: cached.status,
          statusText: cached.statusText,
          headers: cached.headers,
        }
      );
    }


    /* -----------------------------------------------------
     * 添加 / 替换 ECS
     * --------------------------------------------------- */

    const upstreamQuery =
      addOrReplaceEcs(
        query,
        network
      );

    if (!upstreamQuery) {
      return new Response(
        'invalid dns message',
        {
          status: 400,
        }
      );
    }


    /* -----------------------------------------------------
     * Upstream
     * --------------------------------------------------- */

    let upstreamResponse;

    try {
      upstreamResponse =
        await fetch(
          env.UPSTREAM,
          {
            method: 'POST',
            headers: DNS_HEADERS,
            body: upstreamQuery,
          }
        );
    } catch {
      return new Response(
        'upstream unavailable',
        {
          status: 502,
        }
      );
    }


    /*
     * Upstream 非 2xx：
     * 不缓存。
     */
    if (!upstreamResponse.ok) {
      return upstreamResponse;
    }


    /* -----------------------------------------------------
     * Read upstream response
     *
     * 需要读取一次：
     *
     * 1. 计算 TTL
     * 2. 缓存
     * 3. 返回
     * --------------------------------------------------- */

    let responseBody;

    try {
      responseBody =
        new Uint8Array(
          await upstreamResponse.arrayBuffer()
        );
    } catch {
      return new Response(
        'invalid upstream response',
        {
          status: 502,
        }
      );
    }


    /*
     * 验证最基本 DNS Response。
     */
    if (
      responseBody.length < DNS_HEADER_SIZE
    ) {
      return new Response(
        responseBody,
        {
          status: 502,
          headers: {
            'Content-Type':
              'application/dns-message',
          },
        }
      );
    }


    /*
     * TTL 根据真实 DNS Response 决定。
     *
     * 例如：
     *
     * DNS TTL = 60
     * MAX_CACHE_TTL = 25200
     *
     * 实际缓存 = 60 秒
     */
    const ttl =
      getResponseTTL(
        responseBody
      );


    /* -----------------------------------------------------
     * Cache
     * --------------------------------------------------- */

    if (ttl > 0) {
      const cacheResponse =
        new Response(
          responseBody,
          {
            status: 200,
            headers: {
              'Content-Type':
                'application/dns-message',

              'Cache-Control':
                `public, s-maxage=${ttl}`,
            },
          }
        );

      /*
       * 不阻塞当前 DNS Response。
       */
      ctx.waitUntil(
        cache.put(
          cacheKey,
          cacheResponse
        )
      );
    }


    /* -----------------------------------------------------
     * Return
     *
     * 当前请求必须拿到自己的 Transaction ID。
     * --------------------------------------------------- */

    const responseBodyForClient =
      restoreTransactionId(
        responseBody,
        query
      );

    return new Response(
      responseBodyForClient,
      {
        status: 200,
        headers: {
          'Content-Type':
            'application/dns-message',
        },
      }
    );
  },
};
