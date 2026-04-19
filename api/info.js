/**
 * /api/info.js
 * Domain Full Info — aggregates RDAP + DNS + Availability in one call
 * GET  ?domain=example.com&include=whois,dns,availability
 * POST { "domain": "example.com", "include": ["whois","dns","availability"] }
 *
 * Modules (all optional via `include` param, default: all):
 *   whois        — registration dates, registrar, status, nameservers (RDAP)
 *   dns          — A, AAAA, MX, TXT, CNAME, NS records (Cloudflare DoH)
 *   availability — .com availability + 10 popular TLD variants (Verisign)
 *   screenshots  — basic HTTP reachability probe + response metadata
 */

// ─── RDAP servers by TLD (same map as domain-age.js) ────────────────────────
const RDAP_SERVERS = {
  com: 'https://rdap.verisign.com/com/v1',
  net: 'https://rdap.verisign.com/net/v1',
  org: 'https://rdap.publicinterestregistry.org/rdap',
  io:  'https://rdap.nic.io',
  co:  'https://rdap.nic.co',
  ai:  'https://rdap.nic.ai',
  app: 'https://rdap.nic.google',
  dev: 'https://rdap.nic.google',
  info:'https://rdap.afilias.net/rdap/info',
  biz: 'https://rdap.nic.biz',
  us:  'https://rdap.nic.us',
  me:  'https://rdap.nic.me',
  xyz: 'https://rdap.nic.xyz',
  tech:'https://rdap.nic.tech',
  uk:  'https://rdap.nominet.uk',
  de:  'https://rdap.denic.de',
  fr:  'https://rdap.nic.fr',
  nl:  'https://rdap.sidn.nl/rdap',
  eu:  'https://rdap.eu',
  in:  'https://rdap.registry.in',
};
const RDAP_BOOTSTRAP   = 'https://rdap.org/domain';

// Cloudflare DNS-over-HTTPS
const DOH_URL          = 'https://cloudflare-dns.com/dns-query';

// Verisign bulk-check (availability)
const VERISIGN_BULK    = 'https://sugapi.verisign-grs.com/ns-api/2.0/bulk-check';

// TLD variants to check for availability
const VARIANT_TLDS     = ['com','net','org','io','co','ai','app','dev','xyz','info'];

// ─── Helpers ─────────────────────────────────────────────────────────────────

function setCors(res) {
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Content-Type', 'application/json');
}

function validateDomain(raw) {
  const d = raw.trim().toLowerCase()
    .replace(/^https?:\/\//i, '')
    .replace(/^www\./i, '')
    .split('/')[0].split('?')[0];
  if (!d)        return { valid: false, error: 'Empty domain.' };
  if (d.length > 253) return { valid: false, error: 'Domain too long.' };
  const labelRe = /^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$/;
  const parts   = d.split('.');
  if (parts.length < 2) return { valid: false, error: 'Missing TLD.' };
  for (const p of parts) if (!labelRe.test(p)) return { valid: false, error: `Invalid label: "${p}"` };
  return { valid: true, domain: d };
}

function parseDate(s) { if (!s) return null; const d = new Date(s); return isNaN(d) ? null : d; }

function calcAge(from, to = new Date()) {
  if (!from) return null;
  let y = to.getFullYear() - from.getFullYear();
  let m = to.getMonth()    - from.getMonth();
  let d = to.getDate()     - from.getDate();
  if (d < 0) { m--; d += new Date(to.getFullYear(), to.getMonth(), 0).getDate(); }
  if (m < 0) { y--; m += 12; }
  return { years: y, months: m, days: d, total_days: Math.floor((to - from) / 86400000) };
}

function ageCategory(days) {
  if (days < 30)   return 'Very New';
  if (days < 365)  return 'New';
  if (days < 3650) return 'Established';
  return 'Mature';
}

function vCard(arr, field) {
  if (!arr || !Array.isArray(arr[1])) return null;
  const f = arr[1].find(f => f[0] === field);
  return f ? f[3] : null;
}

function hrDate(d) {
  return d ? d.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' }) : null;
}

// ─── Module: WHOIS (RDAP) ───────────────────────────────────────────────────

async function fetchRdap(domain) {
  const tld   = domain.split('.').pop();
  const known = RDAP_SERVERS[tld];
  const urls  = [];
  if (known) urls.push(`${known}/domain/${domain.toUpperCase()}`);
  urls.push(`${RDAP_BOOTSTRAP}/${domain}`);

  for (const url of urls) {
    try {
      const r = await fetch(url, {
        headers: { Accept: 'application/rdap+json,application/json,*/*', 'User-Agent': 'DomainKit/1.0' },
        signal: AbortSignal.timeout(8000),
      });
      if (r.status === 404) return { error: 'not_registered', message: `"${domain}" not found in RDAP — likely unregistered.` };
      if (!r.ok) continue;
      return { data: await r.json() };
    } catch (_) { /* try next */ }
  }
  return { error: 'rdap_unavailable', message: 'All RDAP endpoints failed.' };
}

function buildWhois(rdap, domain) {
  const ev = {};
  (rdap.events || []).forEach(e => { ev[e.eventAction] = e.eventDate; });

  const regDate  = parseDate(ev['registration']);
  const expDate  = parseDate(ev['expiration']);
  const chgDate  = parseDate(ev['last changed']);
  const now      = new Date();
  const age      = calcAge(regDate, now);
  const daysLeft = expDate ? Math.floor((expDate - now) / 86400000) : null;

  const expiryStatus =
    daysLeft === null ? 'unknown' :
    daysLeft < 0      ? 'expired' :
    daysLeft < 30     ? 'expiring_soon' :
    daysLeft < 90     ? 'expiring_this_quarter' : 'active';

  const registrar = rdap.entities?.find(e => e.roles?.includes('registrar'));
  const regName   = registrar ? (vCard(registrar.vcardArray, 'fn') || null) : null;
  const regIana   = registrar?.publicIds?.find(p => p.type === 'IANA Registrar ID')?.identifier || null;
  const regUrl    = registrar?.links?.find(l => l.rel === 'about' || l.type === 'text/html')?.href || null;

  const nameservers = (rdap.nameservers || []).map(n => n.ldhName?.toLowerCase()).filter(Boolean);

  return {
    domain: domain.toLowerCase(),
    registered: true,
    handle: rdap.handle || null,
    status: rdap.status || [],
    dnssec: { signed: rdap.secureDNS?.delegationSigned === true },
    dates: {
      registered:       regDate?.toISOString() || null,
      expiration:       expDate?.toISOString() || null,
      last_changed:     chgDate?.toISOString() || null,
      registered_human: hrDate(regDate),
      expiration_human: hrDate(expDate),
      last_changed_human: hrDate(chgDate),
    },
    age: age ? {
      years: age.years, months: age.months, days: age.days,
      total_days: age.total_days,
      formatted: `${age.years} year${age.years !== 1 ? 's' : ''}, ${age.months} month${age.months !== 1 ? 's' : ''}, ${age.days} day${age.days !== 1 ? 's' : ''}`,
      category: ageCategory(age.total_days),
    } : null,
    expiry: {
      days_remaining: daysLeft,
      status: expiryStatus,
      expires_soon: daysLeft !== null && daysLeft >= 0 && daysLeft < 90,
    },
    registrar: registrar ? {
      name: regName,
      iana_id: regIana,
      url: regUrl,
      handle: registrar.handle || null,
    } : null,
    nameservers,
    rdap_url: rdap.links?.find(l => l.rel === 'self')?.href || null,
  };
}

// ─── Module: DNS ─────────────────────────────────────────────────────────────

const DNS_RECORD_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'CNAME', 'NS', 'SOA'];

async function dohQuery(name, type) {
  try {
    const url = `${DOH_URL}?name=${encodeURIComponent(name)}&type=${type}`;
    const r   = await fetch(url, {
      headers: { Accept: 'application/dns-json' },
      signal: AbortSignal.timeout(5000),
    });
    if (!r.ok) return { type, records: [], error: `HTTP ${r.status}` };
    const j = await r.json();
    if (j.Status !== 0) return { type, records: [] }; // NXDOMAIN or NODATA
    const records = (j.Answer || []).map(ans => {
      const base = { name: ans.name, ttl: ans.TTL, data: ans.data };
      if (type === 'MX') {
        const [pref, ...exch] = ans.data.trim().split(/\s+/);
        return { ...base, priority: parseInt(pref, 10), exchange: exch.join(' ') };
      }
      if (type === 'SOA') {
        const [mname, rname, serial, refresh, retry, expire, minimum] = ans.data.split(/\s+/);
        return { ...base, mname, rname, serial: parseInt(serial), refresh: parseInt(refresh), retry: parseInt(retry), expire: parseInt(expire), minimum: parseInt(minimum) };
      }
      return base;
    });
    return { type, records };
  } catch (e) {
    return { type, records: [], error: e.message };
  }
}

async function buildDns(domain) {
  const results = await Promise.all(DNS_RECORD_TYPES.map(t => dohQuery(domain, t)));
  const map     = {};
  for (const r of results) map[r.type.toLowerCase()] = r.records;

  // Detect hosting/mail providers from records
  const txt  = map.txt?.map(r => r.data) || [];
  const mx   = map.mx?.map(r => r.exchange?.replace(/\.$/, '')) || [];
  const ns   = map.ns?.map(r => r.data?.replace(/\.$/, '')) || [];
  const a    = map.a?.map(r => r.data) || [];

  const mailProvider =
    mx.some(m => m.includes('google'))     ? 'Google Workspace' :
    mx.some(m => m.includes('outlook') || m.includes('microsoft')) ? 'Microsoft 365' :
    mx.some(m => m.includes('mxroute'))    ? 'MXroute' :
    mx.some(m => m.includes('zoho'))       ? 'Zoho Mail' :
    mx.some(m => m.includes('mailgun'))    ? 'Mailgun' :
    mx.some(m => m.includes('sendgrid'))   ? 'SendGrid' :
    mx.some(m => m.includes('protonmail')) ? 'ProtonMail' :
    mx.length ? 'Custom' : null;

  const dnsProvider =
    ns.some(n => n.includes('cloudflare')) ? 'Cloudflare' :
    ns.some(n => n.includes('awsdns'))     ? 'AWS Route 53' :
    ns.some(n => n.includes('azure'))      ? 'Azure DNS' :
    ns.some(n => n.includes('google'))     ? 'Google Cloud DNS' :
    ns.some(n => n.includes('domaincontrol')) ? 'GoDaddy' :
    ns.length ? 'Custom' : null;

  const verifications = txt
    .filter(t => t.startsWith('google-site-verification=') || t.startsWith('v=spf') || t.includes('_domainkey'))
    .map(t => {
      if (t.startsWith('google-site-verification=')) return { type: 'Google Site Verification', value: t };
      if (t.startsWith('v=spf'))  return { type: 'SPF Record', value: t };
      if (t.includes('_domainkey')) return { type: 'DKIM', value: t };
      return { type: 'TXT', value: t };
    });

  const hasIpv6 = (map.aaaa?.length || 0) > 0;
  const hasMail = mx.length > 0;

  return {
    records: map,
    analysis: {
      ip_addresses:    a,
      has_ipv6:        hasIpv6,
      has_mail:        hasMail,
      mail_provider:   mailProvider,
      dns_provider:    dnsProvider,
      verifications,
      record_count:    Object.values(map).reduce((s, r) => s + r.length, 0),
    },
  };
}

// ─── Module: Availability ───────────────────────────────────────────────────

async function buildAvailability(baseName, currentTld) {
  const tlds = [...new Set([currentTld, ...VARIANT_TLDS])].slice(0, 10);
  try {
    const params = new URLSearchParams({
      names: baseName,
      tlds:  tlds.join(','),
      'include-registered': 'true',
    });
    const r = await fetch(`${VERISIGN_BULK}?${params}`, {
      headers: {
        Accept: 'application/json',
        Origin: 'https://dnhub.io',
        Referer: 'https://dnhub.io/',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/147.0.0.0 Safari/537.36',
      },
      signal: AbortSignal.timeout(8000),
    });
    if (!r.ok) throw new Error(`Verisign ${r.status}`);
    const json = await r.json();
    const list = (json.results || []).map(item => {
      const avail = item.availability === 'available';
      return {
        domain:       item.name.toLowerCase(),
        tld:          item.name.split('.').pop().toLowerCase(),
        available:    avail,
        availability: item.availability,
        register_url: avail ? `https://www.namecheap.com/domains/registration/results/?domain=${encodeURIComponent(item.name.toLowerCase())}` : null,
      };
    });
    return {
      base_name: baseName,
      tlds_checked: tlds,
      available:    list.filter(d => d.available),
      registered:   list.filter(d => !d.available),
      all:          list,
    };
  } catch (e) {
    return { error: e.message };
  }
}

// ─── Module: Reachability ───────────────────────────────────────────────────

async function buildReachability(domain) {
  const urls = [`https://${domain}`, `http://${domain}`];
  for (const url of urls) {
    const t0 = Date.now();
    try {
      const r = await fetch(url, {
        method: 'HEAD',
        redirect: 'follow',
        signal: AbortSignal.timeout(6000),
        headers: { 'User-Agent': 'DomainKit/1.0' },
      });
      return {
        reachable:      true,
        url_tried:      url,
        final_url:      r.url || url,
        status_code:    r.status,
        redirected:     r.redirected,
        response_ms:    Date.now() - t0,
        content_type:   r.headers.get('content-type') || null,
        server:         r.headers.get('server') || null,
        x_powered_by:   r.headers.get('x-powered-by') || null,
        cache_control:  r.headers.get('cache-control') || null,
        uses_https:     url.startsWith('https'),
      };
    } catch (_) { /* try http */ }
  }
  return { reachable: false, url_tried: `https://${domain}` };
}

// ─── Main handler ─────────────────────────────────────────────────────────────

export default async function handler(req, res) {
  setCors(res);
  if (req.method === 'OPTIONS') return res.status(204).end();

  // ── Parse inputs ────────────────────────────────────────────────────────────
  let rawDomain, rawInclude;

  if (req.method === 'GET') {
    rawDomain  = req.query.domain || req.query.d || '';
    rawInclude = req.query.include || 'all';
  } else if (req.method === 'POST') {
    const b    = req.body || {};
    rawDomain  = b.domain || b.d || '';
    rawInclude = Array.isArray(b.include) ? b.include.join(',') : (b.include || 'all');
  } else {
    return res.status(405).json({ success: false, error: 'Method not allowed.' });
  }

  if (!rawDomain) {
    return res.status(400).json({
      success: false,
      error: 'Missing `domain` parameter.',
      usage: 'GET /api/info?domain=example.com&include=whois,dns,availability,reachability',
      modules_available: ['whois', 'dns', 'availability', 'reachability'],
    });
  }

  const { valid, domain, error: ve } = validateDomain(String(rawDomain));
  if (!valid) return res.status(400).json({ success: false, error: ve });

  const parts    = domain.split('.');
  const baseName = parts.slice(0, -1).join('.');   // e.g. "example"
  const tld      = parts[parts.length - 1];        // e.g. "com"

  // ── Resolve modules to run ─────────────────────────────────────────────────
  const ALL_MODULES = ['whois', 'dns', 'availability', 'reachability'];
  const include = rawInclude === 'all'
    ? ALL_MODULES
    : rawInclude.split(',').map(s => s.trim().toLowerCase()).filter(m => ALL_MODULES.includes(m));

  if (!include.length) {
    return res.status(400).json({
      success: false,
      error:   `Invalid modules. Choose from: ${ALL_MODULES.join(', ')} or "all".`,
    });
  }

  const t0 = Date.now();

  // ── Run modules concurrently ────────────────────────────────────────────────
  const tasks = {};
  if (include.includes('whois'))        tasks.whois        = fetchRdap(domain);
  if (include.includes('dns'))          tasks.dns          = buildDns(domain);
  if (include.includes('availability')) tasks.availability = buildAvailability(baseName, tld);
  if (include.includes('reachability')) tasks.reachability = buildReachability(domain);

  const settled = Object.fromEntries(
    await Promise.all(
      Object.entries(tasks).map(async ([k, p]) => {
        try   { return [k, { ok: true,  data: await p }]; }
        catch (e) { return [k, { ok: false, error: e.message }]; }
      })
    )
  );

  // ── Build response ──────────────────────────────────────────────────────────
  const output = {
    success:    true,
    domain,
    tld,
    base_name:  baseName,
    modules_run: include,
    checked_at: new Date().toISOString(),
    elapsed_ms: Date.now() - t0,
  };

  // whois
  if (settled.whois) {
    if (!settled.whois.ok) {
      output.whois = { error: settled.whois.error };
    } else {
      const { data, error: re, message: rm } = settled.whois.data;
      if (re) {
        output.whois = { registered: re === 'not_registered' ? false : null, error: re, message: rm };
      } else {
        output.whois = buildWhois(data, domain);
      }
    }
  }

  // dns
  if (settled.dns) {
    output.dns = settled.dns.ok ? settled.dns.data : { error: settled.dns.error };
  }

  // availability
  if (settled.availability) {
    output.availability = settled.availability.ok ? settled.availability.data : { error: settled.availability.error };
  }

  // reachability
  if (settled.reachability) {
    output.reachability = settled.reachability.ok ? settled.reachability.data : { error: settled.reachability.error };
  }

  // ── Smart summary ───────────────────────────────────────────────────────────
  output.summary = {
    domain,
    registered:     output.whois?.registered ?? null,
    age:            output.whois?.age?.formatted || null,
    age_category:   output.whois?.age?.category || null,
    registrar:      output.whois?.registrar?.name || null,
    expires:        output.whois?.dates?.expiration_human || null,
    expiry_status:  output.whois?.expiry?.status || null,
    dns_provider:   output.dns?.analysis?.dns_provider || null,
    mail_provider:  output.dns?.analysis?.mail_provider || null,
    has_ipv6:       output.dns?.analysis?.has_ipv6 ?? null,
    reachable:      output.reachability?.reachable ?? null,
    https:          output.reachability?.uses_https ?? null,
    server:         output.reachability?.server || null,
    tld_variants_available: output.availability?.available?.map(d => d.domain) || null,
  };

  return res.status(200).json(output);
}
