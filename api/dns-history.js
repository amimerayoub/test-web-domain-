/**
 * /api/dns-history.js
 * DNS History & Change Tracker
 *
 * Sources used (all free, no Cloudflare block):
 *  1. SecurityTrails API (free tier: 50 req/month) — full NS history
 *  2. HackerTarget DNS History (free, no key) — NS + A records
 *  3. ViewDNS.info API (free, no key needed for history)
 *  4. RapidDNS.io — live NS lookup
 *  5. Direct live DNS via dns.google JSON API
 *  6. Fallback: parse dnshistory.org (HTML scrape with cache-bypass headers)
 *
 * GET  /api/dns-history?domain=example.com&source=auto
 * POST /api/dns-history  { "domain": "example.com", "source": "auto|hackertarget|securitytrails|live" }
 *
 * Returns:
 *  - current NS, A, MX, TXT records (live)
 *  - historical NS changes with dates
 *  - domain timeline (created, dropped, parked events)
 *  - change count, drop count, age
 */

// ─── CORS ────────────────────────────────────────────────────────────────────
function setCors(res) {
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-SecurityTrails-Key');
  res.setHeader('Content-Type', 'application/json');
}

// ─── Known parking / aftermarket nameservers ─────────────────────────────────
const PARKING_NS = [
  'sedoparking.com','sedo.com','parkingcrew.net','bodis.com','afternic.com',
  'dan.com','undeveloped.com','hugedomains.com','namefind.com','above.com',
  'skenzo.com','hitfarm.com','domainsponsor.com','dsredirection.com',
  'parklogic.com','smartname.com','namedrive.com','moneymade.io','trellian.com',
  'parking.perfectdomain.com','parkpage.foundationapi.com','ns1.parkingcrew.net',
  'domain-for-sale','undeveloped','aftermarket'
];

const REGISTRAR_NS = {
  'domaincontrol.com'       : 'GoDaddy',
  'godaddy.com'             : 'GoDaddy',
  'hostmonster.com'         : 'HostMonster/Bluehost',
  'bluehost.com'            : 'Bluehost',
  'namecheap.com'           : 'Namecheap',
  'registrar-servers.com'   : 'Namecheap',
  'dan.com'                 : 'Dan.com (Aftermarket)',
  'afternic.com'            : 'Afternic (GoDaddy Aftermarket)',
  'namefind.com'            : 'GoDaddy Namefind (Parking)',
  'sedoparking.com'         : 'Sedo (Parking)',
  'spaceship.net'           : 'Spaceship Registrar',
  'awsdns'                  : 'Amazon Route 53',
  'cloudflare.com'          : 'Cloudflare',
  'googledomains.com'       : 'Google Domains',
  'squarespace.com'         : 'Squarespace',
};

function detectNsOwner(ns) {
  const lower = ns.toLowerCase();
  for (const [key, name] of Object.entries(REGISTRAR_NS)) {
    if (lower.includes(key)) return name;
  }
  return null;
}

function isParking(ns) {
  const lower = ns.toLowerCase();
  return PARKING_NS.some(p => lower.includes(p.toLowerCase()));
}

// ─── Validate domain ─────────────────────────────────────────────────────────
function validateDomain(raw) {
  const d = raw.trim().toLowerCase()
    .replace(/^https?:\/\//i,'').replace(/^www\./i,'').split('/')[0].split('?')[0];
  if (!d || d.length > 253) return { valid: false };
  const re = /^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$/;
  const parts = d.split('.');
  if (parts.length < 2) return { valid: false };
  for (const p of parts) if (!re.test(p)) return { valid: false };
  return { valid: true, domain: d };
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SOURCE 1 — Google DNS JSON API (live records, always free)
// ═══════════════════════════════════════════════════════════════════════════════
async function fetchLiveDns(domain) {
  const types = ['NS','A','MX','TXT','SOA','AAAA','CNAME'];
  const results = {};
  await Promise.allSettled(types.map(async type => {
    try {
      const r = await fetch(
        `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`,
        { headers: { 'Accept': 'application/json' } }
      );
      if (!r.ok) return;
      const d = await r.json();
      if (d.Answer?.length) {
        results[type] = d.Answer.map(a => ({
          name: a.name, ttl: a.TTL, data: a.data?.replace(/\.$/, ''),
        }));
      }
    } catch {}
  }));
  return results;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SOURCE 2 — HackerTarget DNS History (free, no key, returns text)
//  URL: https://hackertarget.com/dns-lookup/?q=domain.com
//  Also: https://api.hackertarget.com/dnslookup/?q=domain.com
// ═══════════════════════════════════════════════════════════════════════════════
async function fetchHackerTarget(domain) {
  try {
    const r = await fetch(
      `https://api.hackertarget.com/dnslookup/?q=${encodeURIComponent(domain)}`,
      { headers: { 'User-Agent': 'Mozilla/5.0 (compatible; DomainKit/1.0)' } }
    );
    if (!r.ok) return null;
    const text = await r.text();
    if (text.includes('error') || text.includes('API count')) return null;

    const records = { NS: [], A: [], MX: [], TXT: [] };
    for (const line of text.split('\n')) {
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 3) {
        const type = parts[parts.length - 2]?.toUpperCase();
        const val  = parts[parts.length - 1];
        if (records[type]) records[type].push(val.replace(/\.$/, ''));
      }
    }
    return records;
  } catch { return null; }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SOURCE 3 — SecurityTrails API (free tier: 50/month, optional key)
//  Returns full NS history with dates
// ═══════════════════════════════════════════════════════════════════════════════
async function fetchSecurityTrails(domain, apiKey) {
  if (!apiKey) return null;
  try {
    const [current, history] = await Promise.all([
      fetch(`https://api.securitytrails.com/v1/domain/${domain}`, {
        headers: { 'APIKEY': apiKey, 'Accept': 'application/json' }
      }),
      fetch(`https://api.securitytrails.com/v1/history/${domain}/dns/ns`, {
        headers: { 'APIKEY': apiKey, 'Accept': 'application/json' }
      })
    ]);

    const cur = current.ok ? await current.json() : null;
    const his = history.ok ? await history.json() : null;

    return { current: cur, history: his };
  } catch { return null; }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SOURCE 4 — ViewDNS.info (free web scrape fallback)
// ═══════════════════════════════════════════════════════════════════════════════
async function fetchViewDns(domain) {
  try {
    const r = await fetch(
      `https://viewdns.info/iphistory/?domain=${encodeURIComponent(domain)}`,
      {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
          'Accept': 'text/html,*/*',
          'Referer': 'https://viewdns.info/',
        }
      }
    );
    if (!r.ok) return null;
    const html = await r.text();

    // Extract IP history table rows
    const rows = [];
    const rowRe = /<tr[^>]*>(<td[^>]*>.*?<\/td>)+<\/tr>/gis;
    const cellRe = /<td[^>]*>(.*?)<\/td>/gi;
    let rowMatch;
    while ((rowMatch = rowRe.exec(html)) !== null) {
      const cells = [];
      let cellMatch;
      const rowHtml = rowMatch[0];
      const tempRe  = /<td[^>]*>(.*?)<\/td>/gi;
      while ((cellMatch = tempRe.exec(rowHtml)) !== null) {
        cells.push(cellMatch[1].replace(/<[^>]+>/g, '').trim());
      }
      if (cells.length >= 2 && cells[0].match(/^\d{4}-\d{2}-\d{2}|^\d{1,2}\/\d{1,2}\/\d{4}/)) {
        rows.push({ date: cells[0], ip: cells[1], location: cells[2]||null, owner: cells[3]||null });
      }
    }
    return rows.length ? rows : null;
  } catch { return null; }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SOURCE 5 — dnshistory.org scrape (with bypass headers)
//  Cloudflare protects it but often accessible from server-side
// ═══════════════════════════════════════════════════════════════════════════════
async function fetchDnsHistoryOrg(domain) {
  const urls = [
    `https://dnshistory.org/dns-records/${domain}`,
    `https://dnshistory.org/historical-dns-records/ns/${domain}`,
    `https://dnshistory.org/historical-dns-records/soa/${domain}`,
  ];

  const headers = {
    'Accept'                   : 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language'          : 'en-US,en;q=0.9',
    'User-Agent'               : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Cache-Control'            : 'no-cache',
    'Pragma'                   : 'no-cache',
    'Sec-Fetch-Dest'           : 'document',
    'Sec-Fetch-Mode'           : 'navigate',
    'Sec-Fetch-Site'           : 'none',
    'Upgrade-Insecure-Requests': '1',
  };

  const results = {};
  await Promise.allSettled(urls.map(async (url) => {
    try {
      const r = await fetch(url, { headers });
      if (!r.ok || r.status === 403) return;
      const html = await r.text();
      if (html.includes('cf-browser-verification') || html.includes('jschl-answer')) return; // Cloudflare JS challenge

      const key = url.includes('historical') ? (url.includes('/ns/') ? 'ns_history' : 'soa_history') : 'current';
      results[key] = parseHtmlDnsHistory(html, key);
    } catch {}
  }));

  return Object.keys(results).length ? results : null;
}

// ─── Parse dnshistory.org HTML ────────────────────────────────────────────────
function parseHtmlDnsHistory(html, type) {
  // Strip tags helper
  const strip = s => s.replace(/<[^>]+>/g, '').replace(/&amp;/g,'&').replace(/&lt;/g,'<').replace(/&gt;/g,'>').trim();

  if (type === 'current') {
    // Extract sections: SOA, NS, MX, A, TXT etc.
    const sections = {};
    const secRe    = /<h3>(.*?)<\/h3>[\s\S]*?<p>([\s\S]*?)<\/p>/gi;
    let m;
    while ((m = secRe.exec(html)) !== null) {
      const title = strip(m[1]).replace(/\s*-.*$/, '').trim();
      const body  = strip(m[2]).replace(/\n+/g, '\n').trim();
      if (body) sections[title] = body;
    }
    return sections;
  }

  if (type === 'ns_history' || type === 'soa_history') {
    // Parse date ranges and values
    const records = [];
    const blocks  = html.split(/<b>/i).slice(1);
    for (const block of blocks) {
      const dateMatch = block.match(/^([\d\-]+)\s*->\s*([\d\-]+)<\/b>/);
      if (!dateMatch) continue;
      const from = dateMatch[1], to = dateMatch[2];
      const content = block.replace(/<\/b>/, '').replace(/<[^>]+>/g, '').trim();
      const lines   = content.split('\n').map(l => l.trim()).filter(Boolean);
      const entry   = { from, to, data: {} };
      for (const line of lines) {
        const [key, ...val] = line.split(':');
        if (val.length) entry.data[key.trim()] = val.join(':').trim();
        else if (line && !entry.value) entry.value = line;
      }
      records.push(entry);
    }
    return records;
  }

  return null;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  BUILD TIMELINE from NS history
// ═══════════════════════════════════════════════════════════════════════════════
function buildTimeline(nsHistory) {
  if (!nsHistory || !nsHistory.length) return null;

  const events  = [];
  let prevNs    = null;
  let changes   = 0;
  let drops     = 0;
  let firstDate = null;

  const sorted = [...nsHistory].sort((a, b) => new Date(a.from) - new Date(b.from));

  for (let i = 0; i < sorted.length; i++) {
    const rec  = sorted[i];
    const date = rec.from;
    const ns   = rec.value || rec.data?.MName || '';

    if (!firstDate) firstDate = date;

    // Detect drop (gap > 7 days between records)
    if (prevNs && i > 0) {
      const prevTo  = new Date(sorted[i-1].to);
      const curFrom = new Date(date);
      const gap     = (curFrom - prevTo) / 86400000;

      if (gap > 7) {
        drops++;
        events.push({
          date: sorted[i-1].to,
          type: 'dropped',
          label: 'Domain dropped — nameservers removed',
          ns_before: prevNs,
          ns_after: null,
          gap_days: Math.round(gap),
        });
        events.push({
          date,
          type: 'created',
          label: 'Domain re-registered — nameservers added',
          ns_before: null,
          ns_after: ns,
        });
      } else {
        changes++;
        const parked = isParking(ns);
        events.push({
          date,
          type: parked ? 'parked' : 'ns_change',
          label: parked ? `Domain parked at ${detectNsOwner(ns)||ns}` : 'Nameserver change',
          ns_before: prevNs,
          ns_after: ns,
          owner: detectNsOwner(ns),
          is_parking: parked,
        });
      }
    } else {
      events.push({
        date,
        type: 'created',
        label: 'Domain first seen — nameservers added',
        ns_before: null,
        ns_after: ns,
        owner: detectNsOwner(ns),
      });
    }

    prevNs = ns;
  }

  // Total age
  const ageMs   = firstDate ? Date.now() - new Date(firstDate) : 0;
  const ageDays = Math.floor(ageMs / 86400000);
  const ageYears= Math.floor(ageDays / 365);

  return {
    first_seen : firstDate,
    last_seen  : sorted[sorted.length - 1]?.to || null,
    total_changes: changes,
    total_drops  : drops,
    age_days     : ageDays,
    age_years    : ageYears,
    age_label    : `${ageYears} year${ageYears!==1?'s':''}`,
    events,
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
//  ENRICH live DNS with metadata
// ═══════════════════════════════════════════════════════════════════════════════
function enrichLive(live) {
  if (!live) return live;

  const ns   = (live.NS  || []).map(r => r.data);
  const mx   = (live.MX  || []).map(r => r.data);
  const a    = (live.A   || []).map(r => r.data);
  const txt  = (live.TXT || []).map(r => r.data);
  const soa  = live.SOA?.[0];

  // Detect parking from live NS
  const currentParked  = ns.some(n => isParking(n));
  const currentOwners  = [...new Set(ns.map(n => detectNsOwner(n)).filter(Boolean))];
  const emailProviders = mx.map(m => {
    const d = m.split(' ')[1]||m;
    if (d.includes('google')) return 'Google Workspace';
    if (d.includes('outlook')||d.includes('microsoft')) return 'Microsoft 365';
    if (d.includes('mailgun')) return 'Mailgun';
    if (d.includes('sendgrid')) return 'SendGrid';
    return d.replace(/\.$/, '');
  });

  // Detect TXT verifications
  const verifications = txt.filter(t => t.match(/google|facebook|ms=|v=spf|mailchimp|stripe|apple|amazon|atlassian/i));

  return {
    nameservers: ns,
    a_records  : a,
    mx_records : mx,
    txt_records: txt,
    soa        : soa ? { mname: soa.data } : null,
    meta: {
      is_parked       : currentParked,
      current_owners  : currentOwners,
      email_providers : [...new Set(emailProviders)],
      verifications   : verifications,
      has_email       : mx.length > 0,
      has_ipv4        : a.length > 0,
    },
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
//  MAIN HANDLER
// ═══════════════════════════════════════════════════════════════════════════════
export default async function handler(req, res) {
  setCors(res);
  if (req.method === 'OPTIONS') return res.status(204).end();

  let rawDomain, source, stKey;

  if (req.method === 'GET') {
    rawDomain = req.query.domain || req.query.d || '';
    source    = req.query.source || 'auto';
    stKey     = req.query.st_key || req.headers['x-securitytrails-key'] || '';
  } else if (req.method === 'POST') {
    const b   = req.body || {};
    rawDomain = b.domain || b.d || '';
    source    = b.source || 'auto';
    stKey     = b.st_key || req.headers['x-securitytrails-key'] || '';
  } else {
    return res.status(405).json({ success: false, error: 'Method not allowed' });
  }

  if (!rawDomain) {
    return res.status(400).json({
      success: false,
      error  : 'Missing domain.',
      usage  : {
        GET : '/api/dns-history?domain=example.com',
        POST: 'POST /api/dns-history  { "domain": "example.com" }',
        note: 'Add st_key=YOUR_KEY for SecurityTrails full history (free: 50 req/month at securitytrails.com)',
      },
    });
  }

  const { valid, domain } = validateDomain(String(rawDomain));
  if (!valid) return res.status(400).json({ success: false, error: 'Invalid domain format.' });

  const t0 = Date.now();

  // ── Run all sources in parallel ───────────────────────────────────────────
  const [liveDns, hackerTarget, securityTrails, viewDns, dnsHistoryOrg] =
    await Promise.allSettled([
      fetchLiveDns(domain),
      fetchHackerTarget(domain),
      fetchSecurityTrails(domain, stKey),
      fetchViewDns(domain),
      fetchDnsHistoryOrg(domain),
    ]).then(r => r.map(x => x.status === 'fulfilled' ? x.value : null));

  // ── Enrich live data ──────────────────────────────────────────────────────
  const live = enrichLive(liveDns);

  // ── Build NS history from SecurityTrails (best source if key provided) ────
  let nsHistory = null;
  let timeline  = null;
  let historySource = null;

  if (securityTrails?.history?.records) {
    nsHistory = securityTrails.history.records.map(r => ({
      from : r.first_seen,
      to   : r.last_seen,
      value: (r.values || []).map(v => v.nameserver).join(', '),
    }));
    historySource = 'SecurityTrails';
  } else if (dnsHistoryOrg?.ns_history?.length) {
    nsHistory     = dnsHistoryOrg.ns_history;
    historySource = 'dnshistory.org';
  } else if (dnsHistoryOrg?.soa_history?.length) {
    // Use SOA MName changes as proxy for NS history
    nsHistory = dnsHistoryOrg.soa_history.map(r => ({
      from : r.from, to: r.to, value: r.data?.MName || '',
    }));
    historySource = 'dnshistory.org (SOA)';
  }

  if (nsHistory) {
    timeline = buildTimeline(nsHistory);
  }

  // ── Build domain summary ──────────────────────────────────────────────────
  const isParkedNow = live?.meta?.is_parked || false;
  const hasParkedBefore = timeline?.events?.some(e => e.is_parking) || false;

  const summary = {
    domain,
    is_parked_now  : isParkedNow,
    has_parked_before: hasParkedBefore,
    current_registrar: live?.meta?.current_owners?.[0] || null,
    current_ns       : live?.nameservers || [],
    has_email        : live?.meta?.has_email || false,
    has_ipv4         : live?.meta?.has_ipv4 || false,
    ...(timeline ? {
      first_seen     : timeline.first_seen,
      total_changes  : timeline.total_changes,
      total_drops    : timeline.total_drops,
      age_years      : timeline.age_years,
      age_label      : timeline.age_label,
      headline: `${domain} — ${timeline.total_changes} change${timeline.total_changes!==1?'s':''} and ${timeline.total_drops} drop${timeline.total_drops!==1?'s':''} recorded over ${timeline.age_label}`,
    } : {}),
  };

  // ── IP History from ViewDNS ───────────────────────────────────────────────
  const ipHistory = viewDns?.filter?.(r => r.ip && r.date) || null;

  // ── Sources status ────────────────────────────────────────────────────────
  const sources_used = {
    live_dns        : !!liveDns,
    hackertarget    : !!hackerTarget,
    securitytrails  : !!securityTrails,
    viewdns         : !!viewDns,
    dnshistory_org  : !!dnsHistoryOrg,
    history_source  : historySource,
    st_key_provided : !!stKey,
  };

  return res.status(200).json({
    success    : true,
    domain,
    checked_at : new Date().toISOString(),
    elapsed_ms : Date.now() - t0,

    // ── Summary (human-readable headline) ──────────────────────
    summary,

    // ── Live DNS records ────────────────────────────────────────
    live,

    // ── Historical NS timeline ──────────────────────────────────
    timeline,

    // ── Raw NS history entries ───────────────────────────────────
    ns_history: nsHistory,

    // ── IP History ───────────────────────────────────────────────
    ip_history: ipHistory,

    // ── SecurityTrails current data ──────────────────────────────
    securitytrails_current: securityTrails?.current || null,

    // ── HackerTarget records ─────────────────────────────────────
    hackertarget_records: hackerTarget,

    // ── dnshistory.org raw scrape ────────────────────────────────
    dnshistory_raw: dnsHistoryOrg,

    // ── Sources used ─────────────────────────────────────────────
    sources: sources_used,
  });
}
