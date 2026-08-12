/**
 * Subscription output.
 *
 * Builds VLESS links for a user and renders them in the three formats clients
 * actually ask for. Everything is generated locally: unlike the upstream
 * panel, no third-party subconverter ever sees your configs.
 */

const TLS_PORTS = [443, 2053, 2083, 2087, 2096, 8443];

/**
 * One vless:// URI per entry, labelled for the client's server list.
 *
 * `cleanIps` is optional. When present, each config points at a clean IP
 * while the TLS SNI and WebSocket Host header stay on your real hostname,
 * which is what makes the connection work: Cloudflare routes on the SNI, so
 * any of its edge IPs will do, and the user gets one that is fast on their
 * carrier.
 */
export function buildLinks(user, settings, host, cleanIps = []) {
  const hosts = (settings.hosts?.length ? settings.hosts : [host]).filter(Boolean);
  const port = TLS_PORTS.includes(Number(settings.port)) ? Number(settings.port) : 443;
  const name = settings.subName || 'nova-mini';
  const primary = hosts[0] || host;

  // Clean-IP mode: dial the IP, keep the SNI/Host on the real domain.
  if (cleanIps.length) {
    return cleanIps.map((entry, index) => {
      const [ip, ipPort] = splitEntry(entry, port);
      const params = new URLSearchParams({
        security: 'tls',
        sni: primary,
        fp: 'chrome',
        type: 'ws',
        host: primary,
        path: '/',
        encryption: 'none',
      });
      return `vless://${user.uuid}@${ip}:${ipPort}?${params}#${encodeURIComponent(`${name}-ip${index + 1}`)}`;
    });
  }

  return hosts.map((entry, index) => {
    const params = new URLSearchParams({
      security: 'tls',
      sni: entry,
      fp: 'chrome',
      type: 'ws',
      host: entry,
      path: '/',
      encryption: 'none',
    });
    const label = hosts.length > 1 ? `${name}-${index + 1}` : name;
    return `vless://${user.uuid}@${entry}:${port}?${params}#${encodeURIComponent(label)}`;
  });
}

/** "1.2.3.4" or "1.2.3.4:8443" -> [host, port] */
function splitEntry(entry, fallbackPort) {
  const index = String(entry).lastIndexOf(':');
  if (index === -1) return [entry, fallbackPort];
  const port = Number(entry.slice(index + 1));
  return [entry.slice(0, index), port > 0 && port <= 65535 ? port : fallbackPort];
}

/** v2rayN, Hiddify, Streisand: base64 of newline-separated URIs. */
export function toBase64(links) {
  return btoa(unescape(encodeURIComponent(links.join('\n'))));
}

/** Clash / mihomo. Hand-built YAML so there is no dependency. */
export function toClash(links, user, settings, host, cleanIps = []) {
  const hosts = (settings.hosts?.length ? settings.hosts : [host]).filter(Boolean);
  const port = TLS_PORTS.includes(Number(settings.port)) ? Number(settings.port) : 443;
  const primary = hosts[0] || host;
  const names = [];

  // In clean-IP mode the server is the IP but sni/Host stay on the domain.
  const entries = cleanIps.length
    ? cleanIps.map((ip, i) => {
        const [addr, addrPort] = splitEntry(ip, port);
        return { name: `nova-ip${i + 1}`, server: addr, port: addrPort, sni: primary };
      })
    : hosts.map((h, i) => ({
        name: hosts.length > 1 ? `nova-${i + 1}` : 'nova',
        server: h, port, sni: h,
      }));

  const proxies = entries.map(({ name, server, port: p, sni }) => {
    names.push(name);
    return [
      `  - name: "${name}"`,
      '    type: vless',
      `    server: ${server}`,
      `    port: ${p}`,
      `    uuid: ${user.uuid}`,
      '    network: ws',
      '    tls: true',
      '    udp: false',
      `    servername: ${sni}`,
      '    client-fingerprint: chrome',
      '    ws-opts:',
      '      path: "/"',
      '      headers:',
      `        Host: ${sni}`,
    ].join('\n');
  });

  const list = names.map((n) => `      - "${n}"`).join('\n');
  return [
    'proxies:',
    proxies.join('\n'),
    '',
    'proxy-groups:',
    '  - name: "PROXY"',
    '    type: select',
    '    proxies:',
    list,
    '',
    'rules:',
    '  - GEOIP,private,DIRECT',
    '  - MATCH,PROXY',
    '',
  ].join('\n');
}

/** sing-box. Emitted as JSON so it is valid by construction. */
export function toSingBox(links, user, settings, host, cleanIps = []) {
  const hosts = (settings.hosts?.length ? settings.hosts : [host]).filter(Boolean);
  const port = TLS_PORTS.includes(Number(settings.port)) ? Number(settings.port) : 443;
  const primary = hosts[0] || host;

  const entries = cleanIps.length
    ? cleanIps.map((ip, i) => {
        const [addr, addrPort] = splitEntry(ip, port);
        return { tag: `nova-ip${i + 1}`, server: addr, port: addrPort, sni: primary };
      })
    : hosts.map((h, i) => ({
        tag: hosts.length > 1 ? `nova-${i + 1}` : 'nova',
        server: h, port, sni: h,
      }));

  const outbounds = entries.map(({ tag, server, port: p, sni }) => ({
    type: 'vless',
    tag,
    server,
    server_port: p,
    uuid: user.uuid,
    tls: { enabled: true, server_name: sni, utls: { enabled: true, fingerprint: 'chrome' } },
    transport: { type: 'ws', path: '/', headers: { Host: sni } },
  }));

  return JSON.stringify({
    outbounds: [
      { type: 'selector', tag: 'proxy', outbounds: outbounds.map((o) => o.tag) },
      ...outbounds,
      { type: 'direct', tag: 'direct' },
    ],
  }, null, 2);
}

/**
 * Pick a format from an explicit ?format= or, failing that, the client's
 * User-Agent. Most clients identify themselves clearly enough.
 */
export function chooseFormat(url, userAgent = '') {
  const explicit = (url.searchParams.get('format') || '').toLowerCase();
  if (['base64', 'clash', 'singbox'].includes(explicit)) return explicit;

  const ua = userAgent.toLowerCase();
  if (/clash|mihomo|stash/.test(ua)) return 'clash';
  if (/sing-?box/.test(ua)) return 'singbox';
  return 'base64';
}

export function contentTypeFor(format) {
  if (format === 'clash') return 'text/yaml;charset=utf-8';
  if (format === 'singbox') return 'application/json;charset=utf-8';
  return 'text/plain;charset=utf-8';
}
