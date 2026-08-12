/**
 * Subscription output.
 *
 * Builds VLESS links for a user and renders them in the three formats clients
 * actually ask for. Everything is generated locally: unlike the upstream
 * panel, no third-party subconverter ever sees your configs.
 */

const TLS_PORTS = [443, 2053, 2083, 2087, 2096, 8443];

/** One vless:// URI per host, labelled for the client's server list. */
export function buildLinks(user, settings, host) {
  const hosts = (settings.hosts?.length ? settings.hosts : [host]).filter(Boolean);
  const port = TLS_PORTS.includes(Number(settings.port)) ? Number(settings.port) : 443;
  const name = settings.subName || 'nova-mini';

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

/** v2rayN, Hiddify, Streisand: base64 of newline-separated URIs. */
export function toBase64(links) {
  return btoa(unescape(encodeURIComponent(links.join('\n'))));
}

/** Clash / mihomo. Hand-built YAML so there is no dependency. */
export function toClash(links, user, settings, host) {
  const hosts = (settings.hosts?.length ? settings.hosts : [host]).filter(Boolean);
  const port = TLS_PORTS.includes(Number(settings.port)) ? Number(settings.port) : 443;
  const names = [];

  const proxies = hosts.map((entry, index) => {
    const name = hosts.length > 1 ? `nova-${index + 1}` : 'nova';
    names.push(name);
    return [
      `  - name: "${name}"`,
      '    type: vless',
      `    server: ${entry}`,
      `    port: ${port}`,
      `    uuid: ${user.uuid}`,
      '    network: ws',
      '    tls: true',
      '    udp: false',
      `    servername: ${entry}`,
      '    client-fingerprint: chrome',
      '    ws-opts:',
      '      path: "/"',
      '      headers:',
      `        Host: ${entry}`,
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
export function toSingBox(links, user, settings, host) {
  const hosts = (settings.hosts?.length ? settings.hosts : [host]).filter(Boolean);
  const port = TLS_PORTS.includes(Number(settings.port)) ? Number(settings.port) : 443;

  const outbounds = hosts.map((entry, index) => ({
    type: 'vless',
    tag: hosts.length > 1 ? `nova-${index + 1}` : 'nova',
    server: entry,
    server_port: port,
    uuid: user.uuid,
    tls: { enabled: true, server_name: entry, utls: { enabled: true, fingerprint: 'chrome' } },
    transport: { type: 'ws', path: '/', headers: { Host: entry } },
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
