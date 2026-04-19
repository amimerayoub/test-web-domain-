# DomainKit — All-in-One Domain API Suite

**3 APIs + Website in one Vercel project. Free, no API key required.**

---

## 🚀 Deploy in 60 seconds

```bash
unzip domainkit.zip
cd domainkit
npx vercel --prod
```

Your site + all APIs are live at `https://your-app.vercel.app`

---

## 📁 Project Structure

```
domainkit/
├── api/
│   ├── bulk-check.js    ← API 1: Bulk domain availability (Verisign)
│   ├── domain-age.js    ← API 2: Domain age & info (RDAP)
│   └── check.js         ← API 3: Brand name (domains + social)
├── public/
│   └── index.html       ← Full website with live playground
├── vercel.json          ← Routes, CORS, timeouts
├── package.json
└── README.md
```

---

## 📡 API Endpoints

### 1. Bulk Domain Availability
```
GET  /api/bulk-check?names=Zynora,Veltrix,Datafyno&tlds=com,io,ai
POST /api/bulk-check   { "names": [...], "tlds": [...] }
```
- Up to **100 names** × **10 TLDs** per request
- Powered by **Verisign sugapi** (official .com/.net registry)
- Returns register links for available domains

### 2. Domain Age & RDAP Info
```
GET  /api/domain-age?domain=admin.com
POST /api/domain-age   { "domain": "admin.com" }
```
- Age, registration date, expiry, registrar, nameservers, DNSSEC
- Powered by **official RDAP** (modern WHOIS successor)
- Supports 30+ TLDs with auto-fallback

### 3. Brand Name Checker
```
GET  /api/check?q=mybrand&type=all
POST /api/check   { "q": "mybrand", "type": "domains|social|all" }
```
- Checks **28 domain extensions** + **31 social platforms** in parallel
- Returns profile URLs, register links, availability status
- type options: `all`, `domains`, `social`

---

## 💡 Quick Examples

```bash
# Bulk check
curl "https://your-app.vercel.app/api/bulk-check?names=Datafyno,Nexavo,Zynora&tlds=com,io,ai"

# Domain age
curl "https://your-app.vercel.app/api/domain-age?domain=google.com"

# Brand check
curl "https://your-app.vercel.app/api/check?q=mybrand&type=all"
```

---

## 🌐 Website

After deploy, open `https://your-app.vercel.app` to see:
- Live API playground (no code needed)
- Full documentation
- Copy-paste code examples

> **Important:** After deploying, update `const BASE = ''` in `public/index.html`
> to `const BASE = 'https://your-app.vercel.app'` for the playground to work
> from any domain. When served from the same Vercel domain, it works as-is.
