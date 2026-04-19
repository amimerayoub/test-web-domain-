/**
 * /api/domain-age.js
 * Domain Age & Info — RDAP protocol (free, no API key)
 * GET  ?domain=admin.com
 * POST { "domain": "admin.com" }
 */

const RDAP_SERVERS = {
  com:'https://rdap.verisign.com/com/v1', net:'https://rdap.verisign.com/net/v1',
  org:'https://rdap.publicinterestregistry.org/rdap', io:'https://rdap.nic.io',
  co:'https://rdap.nic.co', ai:'https://rdap.nic.ai', app:'https://rdap.nic.google',
  dev:'https://rdap.nic.google', info:'https://rdap.afilias.net/rdap/info',
  biz:'https://rdap.nic.biz', us:'https://rdap.nic.us', me:'https://rdap.nic.me',
  xyz:'https://rdap.nic.xyz', tech:'https://rdap.nic.tech', uk:'https://rdap.nominet.uk',
  de:'https://rdap.denic.de', fr:'https://rdap.nic.fr', nl:'https://rdap.sidn.nl/rdap',
  eu:'https://rdap.eu', in:'https://rdap.registry.in',
};
const RDAP_BOOTSTRAP = 'https://rdap.org/domain';

function setCors(res) {
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Content-Type', 'application/json');
}

function parseDate(s) { if (!s) return null; const d=new Date(s); return isNaN(d)?null:d; }

function calcAge(from, to=new Date()) {
  if (!from) return null;
  let y=to.getFullYear()-from.getFullYear(), m=to.getMonth()-from.getMonth(), d=to.getDate()-from.getDate();
  if (d<0) { m--; d+=new Date(to.getFullYear(),to.getMonth(),0).getDate(); }
  if (m<0) { y--; m+=12; }
  return { years:y, months:m, days:d, totalDays:Math.floor((to-from)/86400000) };
}

function daysUntil(d) { return d?Math.floor((d-new Date())/86400000):null; }

function ageCategory(n) {
  if (n<30) return 'Very New'; if (n<365) return 'New'; if (n<3650) return 'Established'; return 'Mature';
}

function vCard(arr, field) {
  if (!arr||!Array.isArray(arr[1])) return null;
  const f=arr[1].find(f=>f[0]===field); return f?f[3]:null;
}

function parseEntity(e) {
  if (!e) return null;
  let abuse=null;
  const ab=e.entities?.find(x=>x.roles?.includes('abuse'));
  if (ab) abuse={email:vCard(ab.vcardArray,'email'),phone:vCard(ab.vcardArray,'tel')};
  return {
    handle:e.handle||null, name:vCard(e.vcardArray,'fn')||null,
    org:vCard(e.vcardArray,'org')||null, email:vCard(e.vcardArray,'email')||null,
    tel:vCard(e.vcardArray,'tel')||null, roles:e.roles||[],
    iana_id:e.publicIds?.find(p=>p.type==='IANA Registrar ID')?.identifier||null,
    url:e.links?.find(l=>l.rel==='about'||l.type==='text/html')?.href||null, abuse,
  };
}

function parseRdap(data, domain) {
  const now=new Date(), ev={};
  (data.events||[]).forEach(e=>{ ev[e.eventAction]=e.eventDate; });
  const regDate=parseDate(ev['registration']), expDate=parseDate(ev['expiration']), chgDate=parseDate(ev['last changed']);
  const age=calcAge(regDate,now), daysLeft=daysUntil(expDate);
  const reg=data.entities?.find(e=>e.roles?.includes('registrar'));
  const ns=(data.nameservers||[]).map(n=>n.ldhName?.toUpperCase()).filter(Boolean);
  const hr=d=>d?d.toLocaleDateString('en-US',{year:'numeric',month:'long',day:'numeric'}):null;
  const exSt=daysLeft===null?'unknown':daysLeft<0?'expired':daysLeft<30?'expiring_soon':daysLeft<90?'expiring_this_quarter':'active';
  return {
    domain:domain.toLowerCase(), domain_upper:(data.ldhName||domain).toUpperCase(), handle:data.handle||null,
    age:age?{years:age.years,months:age.months,days:age.days,total_days:age.totalDays,
      formatted:`${age.years} year${age.years!==1?'s':''}, ${age.months} month${age.months!==1?'s':''}, ${age.days} day${age.days!==1?'s':''}`,
      category:ageCategory(age.totalDays)}:null,
    dates:{registered:regDate?.toISOString()||null, expiration:expDate?.toISOString()||null,
      last_changed:chgDate?.toISOString()||null, registered_human:hr(regDate), expiration_human:hr(expDate), last_changed_human:hr(chgDate)},
    expiry:{days_remaining:daysLeft, status:exSt, expires_soon:daysLeft!==null&&daysLeft>=0&&daysLeft<90},
    status:data.status||[], registrar:reg?parseEntity(reg):null,
    nameservers:ns, dnssec:{signed:data.secureDNS?.delegationSigned===true},
    rdap:{self_url:data.links?.find(l=>l.rel==='self')?.href||null, source:'RDAP'},
    summary:{domain:domain.toLowerCase(), age:age?`${age.years}y ${age.months}m ${age.days}d`:'Unknown',
      total_days:age?.totalDays||null, category:age?ageCategory(age.totalDays):'Unknown',
      registered:hr(regDate)||'Unknown', expires:hr(expDate)||'Unknown',
      registrar:reg?vCard(reg.vcardArray,'fn')||'Unknown':'Unknown',
      status:(data.status||[]).join(', ')||'Unknown', nameservers:ns},
    checked_at:now.toISOString(),
  };
}

function validateDomain(raw) {
  const d=raw.trim().toLowerCase().replace(/^https?:\/\//i,'').replace(/^www\./i,'').split('/')[0].split('?')[0];
  if (!d) return {valid:false,error:'Empty domain.'};
  if (d.length>253) return {valid:false,error:'Too long.'};
  const re=/^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$/;
  const parts=d.split('.');
  if (parts.length<2) return {valid:false,error:'Missing TLD.'};
  for (const p of parts) if (!re.test(p)) return {valid:false,error:`Bad label: "${p}"`};
  return {valid:true,domain:d};
}

async function fetchRdap(domain) {
  const parts=domain.split('.'), tld=parts[parts.length-1];
  const known=RDAP_SERVERS[tld];
  const urls=[];
  if (known) urls.push(`${known}/domain/${domain.toUpperCase()}`);
  urls.push(`${RDAP_BOOTSTRAP}/${domain}`);
  let lastErr;
  for (const url of urls) {
    try {
      const r=await fetch(url,{headers:{'Accept':'application/rdap+json,application/json,*/*','User-Agent':'Mozilla/5.0'}});
      if (r.status===404) return {error:'not_found',message:`"${domain}" not found in RDAP.`};
      if (!r.ok) { lastErr=`RDAP ${r.status}`; continue; }
      return {data:await r.json()};
    } catch(e) { lastErr=e.message; }
  }
  return {error:'fetch_failed',message:lastErr};
}

export default async function handler(req, res) {
  setCors(res);
  if (req.method==='OPTIONS') return res.status(204).end();
  let raw;
  if (req.method==='GET')       raw=req.query.domain||req.query.d||'';
  else if (req.method==='POST') raw=req.body?.domain||req.body?.d||'';
  else return res.status(405).json({success:false,error:'Method not allowed'});
  if (!raw) return res.status(400).json({success:false,error:'Missing domain.',usage:'GET /api/domain-age?domain=example.com'});
  const {valid,domain,error:ve}=validateDomain(String(raw));
  if (!valid) return res.status(400).json({success:false,error:ve});
  const t0=Date.now();
  const {data,error:re,message:rm}=await fetchRdap(domain);
  if (re) return res.status(re==='not_found'?404:502).json({success:false,domain,error:re,message:rm});
  return res.status(200).json({success:true,...parseRdap(data,domain),elapsed_ms:Date.now()-t0,raw_rdap:data});
}
