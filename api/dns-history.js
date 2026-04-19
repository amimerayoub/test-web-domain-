/**
 * /api/dns-history.js  — v2.0
 * DNS History & Change Tracker — ALL BUGS FIXED
 *
 * ROOT CAUSE OF EMPTY RESPONSES:
 *  1. vufiqee.com is UNREGISTERED → NXDOMAIN → empty records is CORRECT
 *  2. HackerTarget blocked this server (removed, replaced)
 *  3. ViewDNS HTML parser was wrong (fixed)
 *  4. dns.google returns 403 from some servers (Cloudflare DoH added as primary)
 *  5. No "domain not registered" message in response (fixed with clear status)
 *
 * Sources (v2):
 *  1. Cloudflare DoH + Google DoH  — live DNS (with NXDOMAIN detection)
 *  2. RDAP (Verisign + rdap.org)   — registration dates, status, registrar
 *  3. SecurityTrails               — full NS history (optional free key)
 *  4. dnshistory.org               — HTML scrape (best-effort, Cloudflare may block)
 *  5. ViewDNS.info                 — IP history (best-effort)
 *
 * GET  /api/dns-history?domain=example.com
 * POST /api/dns-history  { "domain": "example.com", "st_key": "optional" }
 */

// ─── CORS ─────────────────────────────────────────────────────────────────────
function setCors(res) {
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-SecurityTrails-Key');
  res.setHeader('Content-Type', 'application/json');
}

// ─── Parking / aftermarket NS detection ───────────────────────────────────────
const PARKING_KEYWORDS = ['sedoparking','sedo.com','parkingcrew','bodis.com','afternic','dan.com','undeveloped','hugedomains','namefind','above.com','skenzo','hitfarm','domainsponsor','trellian','parklogic','smartname','namedrive','moneymade','foundationapi'];

const NS_OWNERS = {
  'domaincontrol.com':'GoDaddy','godaddy.com':'GoDaddy','hostmonster.com':'HostMonster/Bluehost',
  'bluehost.com':'Bluehost','namecheap.com':'Namecheap','registrar-servers.com':'Namecheap',
  'dan.com':'Dan.com (Aftermarket)','afternic.com':'Afternic (GoDaddy Aftermarket)',
  'namefind.com':'GoDaddy Namefind (Parking)','sedoparking.com':'Sedo Parking',
  'spaceship.net':'Spaceship Registrar','awsdns':'Amazon Route 53',
  'cloudflare.com':'Cloudflare','googledomains.com':'Google Domains',
  'squarespace.com':'Squarespace','name.com':'Name.com','gandi.net':'Gandi',
  'porkbun.com':'Porkbun','dynadot.com':'Dynadot','hover.com':'Hover',
  'networksolutions.com':'Network Solutions','enom.com':'eNom',
};

function detectOwner(ns) {
  if (!ns) return null;
  const l = ns.toLowerCase();
  for (const [k, v] of Object.entries(NS_OWNERS)) if (l.includes(k)) return v;
  const p = l.split('.');
  return p.length >= 2 ? `${p[p.length-2]}.${p[p.length-1]}` : null;
}
function isParking(ns) { return ns ? PARKING_KEYWORDS.some(k => ns.toLowerCase().includes(k)) : false; }

// ─── Domain validation ────────────────────────────────────────────────────────
function validateDomain(raw) {
  const d = raw.trim().toLowerCase().replace(/^https?:\/\//i,'').replace(/^www\./i,'').split(/[/?#]/)[0];
  if (!d || d.length > 253) return { valid:false, error:'Domain empty or too long.' };
  const re = /^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$/;
  const parts = d.split('.');
  if (parts.length < 2) return { valid:false, error:'Missing TLD.' };
  for (const p of parts) if (!re.test(p)) return { valid:false, error:`Invalid label: "${p}"` };
  return { valid:true, domain:d };
}

// ─── Fetch with timeout ───────────────────────────────────────────────────────
async function ft(url, opts={}, ms=8000) {
  const ac = new AbortController();
  const tm = setTimeout(() => ac.abort(), ms);
  try {
    const r = await fetch(url, { ...opts, signal: ac.signal });
    clearTimeout(tm); return r;
  } catch(e) { clearTimeout(tm); throw e; }
}

// ─── Strip HTML tags ──────────────────────────────────────────────────────────
function strip(s) {
  return s.replace(/<[^>]+>/g,'').replace(/&amp;/g,'&').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&nbsp;/g,' ').replace(/&#\d+;/g,'').trim();
}

// ══════════════════════════════════════════════════════════════════════════════
// SOURCE 1 — DNS over HTTPS (Cloudflare primary, Google fallback)
// Key fix: detect NXDOMAIN (Status=3) = domain NOT registered
// ══════════════════════════════════════════════════════════════════════════════
async function fetchLiveDns(domain) {
  const TYPES = ['NS','A','MX','TXT','SOA','AAAA','CNAME'];
  const PROVIDERS = [
    { name:'cloudflare', base:'https://cloudflare-dns.com/dns-query', headers:{'Accept':'application/dns-json'} },
    { name:'google',     base:'https://dns.google/resolve',           headers:{'Accept':'application/json'} },
  ];

  const records = {};
  let nxdomain  = null;
  let provider  = null;

  // Find working provider with NS query
  for (const p of PROVIDERS) {
    try {
      const r = await ft(`${p.base}?name=${encodeURIComponent(domain)}&type=NS`, { headers: p.headers }, 7000);
      if (!r.ok) continue;
      const d = await r.json();
      provider = p.name;
      nxdomain = d.Status === 3; // NXDOMAIN
      if (d.Answer?.length) {
        records.NS = d.Answer.map(a => ({ ttl:a.TTL, data:a.data?.replace(/\.$/,'') }));
      }
      break;
    } catch {}
  }

  if (!provider) return { records:{}, nxdomain:null, provider:null };

  // Fetch remaining types in parallel
  const prov = PROVIDERS.find(p => p.name === provider);
  await Promise.allSettled(TYPES.filter(t=>t!=='NS').map(async type => {
    try {
      const r = await ft(`${prov.base}?name=${encodeURIComponent(domain)}&type=${type}`, { headers:prov.headers }, 6000);
      if (!r.ok) return;
      const d = await r.json();
      if (d.Answer?.length) records[type] = d.Answer.map(a => ({ ttl:a.TTL, data:a.data?.replace(/\.$/, '') }));
    } catch {}
  }));

  return { records, nxdomain, provider };
}

// ══════════════════════════════════════════════════════════════════════════════
// SOURCE 2 — RDAP (confirms registration + gets dates even if no NS history)
// ══════════════════════════════════════════════════════════════════════════════
const RDAP = {
  com:'https://rdap.verisign.com/com/v1', net:'https://rdap.verisign.com/net/v1',
  org:'https://rdap.publicinterestregistry.org/rdap', io:'https://rdap.nic.io',
  co:'https://rdap.nic.co', ai:'https://rdap.nic.ai', app:'https://rdap.nic.google',
  dev:'https://rdap.nic.google', info:'https://rdap.afilias.net/rdap/info',
  biz:'https://rdap.nic.biz', us:'https://rdap.nic.us', me:'https://rdap.nic.me',
  xyz:'https://rdap.nic.xyz', tech:'https://rdap.nic.tech', uk:'https://rdap.nominet.uk',
};

async function fetchRdap(domain) {
  const tld  = domain.split('.').pop();
  const urls = [];
  if (RDAP[tld]) urls.push(`${RDAP[tld]}/domain/${domain.toUpperCase()}`);
  urls.push(`https://rdap.org/domain/${domain}`);

  for (const url of urls) {
    try {
      const r = await ft(url, { headers:{'Accept':'application/rdap+json, application/json'} }, 8000);
      if (r.status === 404) return { registered:false };
      if (!r.ok) continue;
      const d = await r.json();
      const ev = {};
      (d.events||[]).forEach(e => { ev[e.eventAction] = e.eventDate; });
      const hr = s => s ? new Date(s).toLocaleDateString('en-US',{year:'numeric',month:'long',day:'numeric'}) : null;
      const reg = d.entities?.find(e=>e.roles?.includes('registrar'));
      const regName = reg?.vcardArray?.[1]?.find(f=>f[0]==='fn')?.[3] || null;
      return {
        registered: true, handle:d.handle||null, status:d.status||[],
        registered_date: ev['registration']||null,
        expiration_date: ev['expiration']||null,
        registered_human: hr(ev['registration']),
        expiration_human: hr(ev['expiration']),
        registrar_name: regName,
        nameservers: (d.nameservers||[]).map(n=>n.ldhName?.toUpperCase().replace(/\.$/,'')).filter(Boolean),
      };
    } catch {}
  }
  return { registered:null }; // unknown
}

// ══════════════════════════════════════════════════════════════════════════════
// SOURCE 3 — SecurityTrails (full NS history, optional free key)
// ══════════════════════════════════════════════════════════════════════════════
async function fetchSecurityTrails(domain, key) {
  if (!key) return null;
  try {
    const h = { 'APIKEY':key, 'Accept':'application/json' };
    const [c,h2] = await Promise.allSettled([
      ft(`https://api.securitytrails.com/v1/domain/${domain}`, {headers:h}, 10000),
      ft(`https://api.securitytrails.com/v1/history/${domain}/dns/ns`, {headers:h}, 10000),
    ]);
    return {
      current: c.status==='fulfilled'&&c.value.ok ? await c.value.json() : null,
      history: h2.status==='fulfilled'&&h2.value.ok ? await h2.value.json() : null,
    };
  } catch { return null; }
}

// ══════════════════════════════════════════════════════════════════════════════
// SOURCE 4 — dnshistory.org scrape (Cloudflare may block, best-effort)
// ══════════════════════════════════════════════════════════════════════════════
async function fetchDnsHistoryOrg(domain) {
  const H = {
    'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept':'text/html,application/xhtml+xml,*/*;q=0.9',
    'Accept-Language':'en-US,en;q=0.9',
    'Cache-Control':'no-cache',
    'Sec-Fetch-Dest':'document','Sec-Fetch-Mode':'navigate','Sec-Fetch-Site':'none',
  };

  const endpoints = [
    [`https://dnshistory.org/historical-dns-records/ns/${domain}`, 'ns_history'],
    [`https://dnshistory.org/historical-dns-records/soa/${domain}`,'soa_history'],
    [`https://dnshistory.org/dns-records/${domain}`,               'current'],
  ];

  const out = {};
  await Promise.allSettled(endpoints.map(async ([url, key]) => {
    try {
      const r = await ft(url, {headers:H}, 10000);
      if (!r.ok) return;
      const html = await r.text();
      // Detect Cloudflare challenge
      if (html.includes('cf-browser-verification')||html.includes('jschl_answer')||html.length < 2000) {
        out[key] = { blocked:true }; return;
      }
      out[key] = key==='current' ? parseCurrentDnsHistory(html) : parseHistDnsHistory(html);
    } catch(e) { out[key]={error:e.message}; }
  }));

  return Object.keys(out).length ? out : null;
}

function parseCurrentDnsHistory(html) {
  const out = {};
  const re  = /<h3[^>]*>(.*?)<\/h3>\s*<p[^>]*>([\s\S]*?)<\/p>/gi;
  let m;
  while ((m=re.exec(html))!==null) {
    const title   = strip(m[1]).replace(/\s*-\s*\(.*\)/,'').trim();
    const content = strip(m[2]).replace(/\n{3,}/g,'\n\n').trim();
    if (content) out[title] = content;
  }
  return out;
}

function parseHistDnsHistory(html) {
  const records = [];
  const parts   = html.split(/<b>/i).slice(1);
  for (const part of parts) {
    const dm = part.match(/^(\d{4}-\d{2}-\d{2})\s*->\s*(\d{4}-\d{2}-\d{2})<\/b>/);
    if (!dm) continue;
    const [,from,to] = dm;
    const body  = strip(part.replace(/<\/b>/,'')).trim();
    const lines = body.split('\n').map(l=>l.trim()).filter(l=>l&&l!==from&&l!==to);
    const entry = { from, to, fields:{} };
    let firstVal = null;
    for (const line of lines) {
      const ci = line.indexOf(':');
      if (ci>0&&ci<25) { entry.fields[line.slice(0,ci).trim()] = line.slice(ci+1).trim(); }
      else if (!firstVal&&line.length>2) firstVal=line;
    }
    entry.value = entry.fields.MName || firstVal || null;
    if (entry.value) records.push(entry);
  }
  return records;
}

// ══════════════════════════════════════════════════════════════════════════════
// SOURCE 5 — ViewDNS.info IP History (best-effort)
// ══════════════════════════════════════════════════════════════════════════════
async function fetchIpHistory(domain) {
  try {
    const r = await ft(
      `https://viewdns.info/iphistory/?domain=${encodeURIComponent(domain)}`,
      { headers:{ 'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0', 'Accept':'text/html,*/*', 'Referer':'https://viewdns.info/' } },
      8000
    );
    if (!r.ok) return null;
    const html = await r.text();
    if (html.includes('cf-browser-verification')) return null;

    const rows = [];
    const tdRe = /<td[^>]*class="td"[^>]*>([\s\S]*?)<\/td>/gi;
    const cells=[];
    let m;
    while ((m=tdRe.exec(html))!==null) cells.push(strip(m[1]));
    for (let i=0;i<cells.length-3;i+=4) {
      const [ip,loc,owner,date]=cells.slice(i,i+4);
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) rows.push({ip,location:loc,owner,date});
    }
    return rows.length ? rows : null;
  } catch { return null; }
}

// ══════════════════════════════════════════════════════════════════════════════
// BUILD TIMELINE
// ══════════════════════════════════════════════════════════════════════════════
function extractNsHistory(st, dnsHist) {
  if (st?.history?.records?.length) {
    return { source:'SecurityTrails', records: st.history.records.map(r=>({
      from:r.first_seen, to:r.last_seen,
      value:(r.values||[]).map(v=>v.nameserver?.replace(/\.$/,'')).join(', '),
    })).filter(r=>r.from&&r.value) };
  }
  if (Array.isArray(dnsHist?.ns_history)&&dnsHist.ns_history.length) {
    return { source:'dnshistory.org (NS)', records: dnsHist.ns_history.filter(r=>r.from&&r.value) };
  }
  if (Array.isArray(dnsHist?.soa_history)&&dnsHist.soa_history.length) {
    return { source:'dnshistory.org (SOA)', records: dnsHist.soa_history.filter(r=>r.from&&r.fields?.MName).map(r=>({from:r.from,to:r.to,value:r.fields.MName})) };
  }
  return null;
}

function buildTimeline(nsRecs, rdap) {
  if (!nsRecs?.length && !rdap?.registered_date) return null;
  const events=[], sorted = (nsRecs||[]).filter(r=>r.from&&r.value).sort((a,b)=>new Date(a.from)-new Date(b.from));
  let changes=0, drops=0, firstDate=null;

  if (sorted.length) {
    firstDate = sorted[0].from;
    for (let i=0;i<sorted.length;i++) {
      const {from:date,value:ns} = sorted[i];
      if (i===0) { events.push({date,type:'created',label:'Domain first seen — nameservers added',ns_after:ns,owner:detectOwner(ns),is_parking:isParking(ns)}); continue; }
      const gap = Math.round((new Date(date)-new Date(sorted[i-1].to))/86400000);
      if (gap>10) {
        drops++;
        events.push({date:sorted[i-1].to,type:'dropped',label:'Domain dropped — nameservers removed',ns_before:sorted[i-1].value,gap_days:gap});
        events.push({date,type:'created',label:'Domain re-registered — nameservers added',ns_after:ns,owner:detectOwner(ns),is_parking:isParking(ns)});
      } else {
        changes++;
        const p=isParking(ns);
        events.push({date,type:p?'parked':'ns_change',label:p?`Domain parked → ${detectOwner(ns)||ns}`:'Nameserver changed',ns_before:sorted[i-1].value,ns_after:ns,owner:detectOwner(ns),is_parking:p});
      }
    }
  } else if (rdap?.registered_date) {
    firstDate = rdap.registered_date.split('T')[0];
    events.push({date:firstDate,type:'created',label:'Domain registered (via RDAP)',owner:rdap.registrar_name});
  }

  if (!events.length) return null;
  const ageDays  = firstDate ? Math.floor((Date.now()-new Date(firstDate))/86400000) : 0;
  const ageYears = Math.floor(ageDays/365);
  const ageMons  = Math.floor((ageDays%365)/30);
  const ageLabel = ageYears>0 ? `${ageYears}y${ageMons>0?` ${ageMons}m`:''}` : `${Math.floor(ageDays/30)} months`;

  return {
    first_seen:firstDate, last_seen:sorted[sorted.length-1]?.to||null,
    total_changes:changes, total_drops:drops,
    age_days:ageDays, age_years:ageYears, age_label:ageLabel,
    has_been_parked:events.some(e=>e.is_parking),
    headline: sorted.length
      ? `${changes} change${changes!==1?'s':''} and ${drops} drop${drops!==1?'s':''} recorded over ${ageYears>0?`${ageYears} year${ageYears!==1?'s':''}`:`${Math.floor(ageDays/30)} months`}`
      : 'Recently registered — limited history available',
    events,
  };
}

function enrichLive(doh) {
  if (!doh) return null;
  const {records,nxdomain,provider} = doh;
  const ns   =(records.NS   ||[]).map(r=>r.data).filter(Boolean);
  const a    =(records.A    ||[]).map(r=>r.data).filter(Boolean);
  const aaaa =(records.AAAA ||[]).map(r=>r.data).filter(Boolean);
  const mx   =(records.MX   ||[]).map(r=>r.data).filter(Boolean);
  const txt  =(records.TXT  ||[]).map(r=>r.data).filter(Boolean);
  const soa  = records.SOA?.[0];
  const cname=(records.CNAME||[]).map(r=>r.data).filter(Boolean);
  const emailProv=[...new Set(mx.map(m=>{
    const d=(m.split(' ')[1]||m).toLowerCase();
    return d.includes('google')?'Google Workspace':d.includes('outlook')||d.includes('microsoft')?'Microsoft 365':d.includes('mailgun')?'Mailgun':d.includes('sendgrid')?'SendGrid':d.includes('amazonses')?'Amazon SES':d.includes('zoho')?'Zoho Mail':d.replace(/\.$/,'');
  }))];
  return {
    nameservers:ns, a_records:a, aaaa_records:aaaa, mx_records:mx,
    txt_records:txt, cname_records:cname, soa:soa?{data:soa.data,ttl:soa.ttl}:null,
    provider, nxdomain,
    meta:{
      is_parked:ns.some(n=>isParking(n)), current_owners:[...new Set(ns.map(detectOwner).filter(Boolean))],
      email_providers:emailProv, has_email:mx.length>0, has_ipv4:a.length>0,
      has_ipv6:aaaa.length>0, has_cname:cname.length>0,
      spf_record:txt.find(t=>t.startsWith('v=spf1'))||null,
      dmarc_record:txt.find(t=>t.startsWith('v=DMARC1'))||null,
      verifications:txt.filter(t=>/google|facebook|ms=|mailchimp|stripe|atlassian|shopify/i.test(t)),
    },
  };
}

// ══════════════════════════════════════════════════════════════════════════════
// MAIN HANDLER
// ══════════════════════════════════════════════════════════════════════════════
export default async function handler(req, res) {
  setCors(res);
  if (req.method==='OPTIONS') return res.status(204).end();

  let rawDomain, stKey;
  if (req.method==='GET')       { rawDomain=req.query.domain||req.query.d||''; stKey=req.query.st_key||req.headers['x-securitytrails-key']||''; }
  else if (req.method==='POST') { const b=req.body||{}; rawDomain=b.domain||b.d||''; stKey=b.st_key||req.headers['x-securitytrails-key']||''; }
  else return res.status(405).json({success:false,error:'Method not allowed'});

  if (!rawDomain) return res.status(400).json({
    success:false, error:'Missing domain.',
    usage:{ GET:'/api/dns-history?domain=example.com', POST:'{ "domain":"example.com","st_key":"optional" }' },
    note:'For full NS history add st_key from https://securitytrails.com (free 50 req/month)',
  });

  const {valid,domain,error:ve}=validateDomain(String(rawDomain));
  if (!valid) return res.status(400).json({success:false,error:ve||'Invalid domain'});

  const t0=Date.now();

  // Run all sources in parallel
  const [dohR,rdapR,stR,dnsHistR,ipHistR]=await Promise.allSettled([
    fetchLiveDns(domain), fetchRdap(domain),
    fetchSecurityTrails(domain,stKey), fetchDnsHistoryOrg(domain), fetchIpHistory(domain),
  ]).then(r=>r.map(x=>x.status==='fulfilled'?x.value:null));

  const live = enrichLive(dohR);
  const rdap = rdapR;

  // Determine registration status from multiple signals
  const isNxdomain = dohR?.nxdomain ?? false;
  let registered   = null;
  if      (rdap?.registered===false)   registered=false;
  else if (rdap?.registered===true)    registered=true;
  else if (live?.nameservers?.length)  registered=true;
  else if (isNxdomain)                 registered=false;

  // NS history + timeline
  const nsHistData = extractNsHistory(stR, dnsHistR);
  const timeline   = buildTimeline(nsHistData?.records, rdap);

  const currentNs   = live?.nameservers||rdap?.nameservers||[];
  const isParkedNow = currentNs.some(n=>isParking(n));
  const owners      = [...new Set(currentNs.map(detectOwner).filter(Boolean))];

  const summary = {
    domain,
    registration_status: registered===false?'unregistered':registered===true?'registered':'unknown',
    registered,
    is_parked_now:isParkedNow,
    has_parked_before:timeline?.has_been_parked||false,
    current_registrar:owners[0]||rdap?.registrar_name||null,
    current_ns:currentNs,
    registered_date:rdap?.registered_date||null,
    expiration_date:rdap?.expiration_date||null,
    registered_human:rdap?.registered_human||null,
    expiration_human:rdap?.expiration_human||null,
    has_email:live?.meta?.has_email||false,
    has_ipv4:live?.meta?.has_ipv4||false,
    ...(registered===false ? {
      headline:`${domain} — Domain is NOT registered (NXDOMAIN — available to register)`,
      tip:'Use /api/bulk-check to check availability across TLDs',
    } : timeline ? {
      headline:`${domain} — ${timeline.headline}`,
      first_seen:timeline.first_seen, total_changes:timeline.total_changes,
      total_drops:timeline.total_drops, age_label:timeline.age_label,
    } : {
      headline:`${domain} — Registered but no NS history found from free sources`,
      tip:stKey?'Try again with a valid SecurityTrails key':'Add st_key=YOUR_KEY for full NS history (free at securitytrails.com, 50 req/month)',
    }),
  };

  return res.status(200).json({
    success:true, domain,
    checked_at:new Date().toISOString(), elapsed_ms:Date.now()-t0,
    registered, registration_status:summary.registration_status,
    summary, live,
    rdap:rdap?.registered!==undefined?{
      registered:rdap.registered, handle:rdap.handle||null, status:rdap.status||[],
      registered_date:rdap.registered_date||null, expiration_date:rdap.expiration_date||null,
      registered_human:rdap.registered_human||null, expiration_human:rdap.expiration_human||null,
      registrar_name:rdap.registrar_name||null, nameservers:rdap.nameservers||[],
    }:null,
    timeline, ns_history:nsHistData?.records||null, ns_history_source:nsHistData?.source||null,
    ip_history:ipHistR||null,
    securitytrails_data:stR||null, dnshistory_raw:dnsHistR||null,
    sources:{
      doh_provider:dohR?.provider||null, live_dns:!!dohR,
      live_dns_nxdomain:isNxdomain, rdap:rdap?.registered!==undefined,
      rdap_registered:rdap?.registered??null, securitytrails:!!(stR?.history||stR?.current),
      viewdns:!!ipHistR, dnshistory_org:!!(dnsHistR&&!dnsHistR.ns_history?.blocked),
      history_source:nsHistData?.source||null, st_key_provided:!!stKey,
      records_found:!!nsHistData?.records?.length,
    },
  });
}
