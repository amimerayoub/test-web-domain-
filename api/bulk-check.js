/**
 * /api/bulk-check.js
 * Bulk Domain Availability — Verisign sugapi
 * GET  ?names=Zynora,Veltrix&tlds=com,io
 * POST { "names": [...], "tlds": [...] }
 */

const VERISIGN_API = 'https://sugapi.verisign-grs.com/ns-api/2.0/bulk-check';
const MAX_NAMES    = 100;
const MAX_TLDS     = 10;

function setCors(res) {
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Content-Type', 'application/json');
}

function cleanName(s) { return s.trim().replace(/\..*$/, '').replace(/[^a-zA-Z0-9\-]/g, ''); }
function cleanTld(s)  { return s.trim().replace(/^\./, '').toLowerCase().replace(/[^a-z0-9\-]/g, ''); }
function chunk(arr, n) { const r=[]; for(let i=0;i<arr.length;i+=n) r.push(arr.slice(i,i+n)); return r; }

async function verisignBulk(names, tlds, includeRegistered) {
  const params = new URLSearchParams({ names: names.join(','), tlds: tlds.join(','), 'include-registered': String(includeRegistered) });
  const res = await fetch(`${VERISIGN_API}?${params}`, {
    headers: {
      'Accept': 'application/json, */*',
      'Accept-Language': 'en-GB,en;q=0.5',
      'Origin': 'https://dnhub.io',
      'Referer': 'https://dnhub.io/',
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/147.0.0.0 Safari/537.36',
      'Sec-Fetch-Dest': 'empty', 'Sec-Fetch-Mode': 'cors', 'Sec-Fetch-Site': 'cross-site', 'Sec-GPC': '1',
    }
  });
  if (!res.ok) throw new Error(`Verisign ${res.status}`);
  return res.json();
}

function enrich(results) {
  const available = [], registered = [], byName = {}, byTld = {};
  for (const item of results) {
    const dot  = item.name.lastIndexOf('.');
    const base = dot > -1 ? item.name.slice(0, dot)  : item.name;
    const tld  = dot > -1 ? item.name.slice(dot + 1) : '';
    const ok   = item.availability === 'available';
    const e    = {
      domain: item.name.toLowerCase(), name: base, tld: tld.toLowerCase(),
      availability: item.availability, available: ok, taken: !ok,
      register_url: ok ? `https://www.namecheap.com/domains/registration/results/?domain=${encodeURIComponent(item.name.toLowerCase())}` : null,
      whois_url: `https://lookup.icann.org/en/lookup?name=${encodeURIComponent(item.name.toLowerCase())}`,
    };
    if (ok) available.push(e); else registered.push(e);
    if (!byName[base]) byName[base] = { name: base, results: [] }; byName[base].results.push(e);
    if (!byTld[tld])   byTld[tld]  = { tld,  results: [] };        byTld[tld].results.push(e);
  }
  return { available, registered, byName, byTld };
}

export default async function handler(req, res) {
  setCors(res);
  if (req.method === 'OPTIONS') return res.status(204).end();

  let rawNames, rawTlds, includeRegistered = true;
  if (req.method === 'GET') {
    rawNames = (req.query.names || req.query.name || '').split(',').map(s=>s.trim()).filter(Boolean);
    rawTlds  = (req.query.tlds  || req.query.tld  || 'com').split(',').map(s=>s.trim()).filter(Boolean);
    includeRegistered = req.query['include-registered'] !== 'false';
  } else if (req.method === 'POST') {
    const b  = req.body || {};
    const n  = b.names || b.name || [];
    const t  = b.tlds  || b.tld  || ['com'];
    rawNames = (Array.isArray(n) ? n : String(n).split(',')).map(s=>s.trim()).filter(Boolean);
    rawTlds  = (Array.isArray(t) ? t : String(t).split(',')).map(s=>s.trim()).filter(Boolean);
    includeRegistered = b['include-registered'] !== false;
  } else return res.status(405).json({ success:false, error:'Method not allowed' });

  if (!rawNames.length) return res.status(400).json({ success:false, error:'No names provided.', usage:'GET /api/bulk-check?names=Zynora,Veltrix&tlds=com,io' });

  const names  = [...new Set(rawNames.map(cleanName).filter(Boolean))];
  const tlds   = [...new Set(rawTlds.map(cleanTld).filter(Boolean))].slice(0, MAX_TLDS);
  if (!names.length) return res.status(400).json({ success:false, error:'All names were invalid.' });

  const t0 = Date.now();
  const allResults = [], errors = [];
  await Promise.allSettled(chunk(names, MAX_NAMES).map(async batch => {
    try { const d = await verisignBulk(batch, tlds, includeRegistered); if (Array.isArray(d.results)) allResults.push(...d.results); }
    catch(e) { errors.push(e.message); }
  }));

  if (!allResults.length && errors.length) return res.status(502).json({ success:false, error:'Upstream failed.', details:errors });

  const { available, registered, byName, byTld } = enrich(allResults);

  return res.status(200).json({
    success:true, checked_at:new Date().toISOString(), elapsed_ms: Date.now()-t0,
    input: { names, tlds, total_checked: allResults.length },
    summary: { total:allResults.length, available:available.length, registered:registered.length, availability_rate:`${allResults.length ? Math.round(available.length/allResults.length*100) : 0}%` },
    results: { available, registered, all: allResults.map(r=>({ domain:r.name.toLowerCase(), availability:r.availability, available:r.availability==='available' })) },
    by_name: Object.values(byName), by_tld: Object.values(byTld),
    errors: errors.length ? errors : undefined,
  });
}
