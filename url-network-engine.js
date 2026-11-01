/* ============================================================
   XEROX — url-network-engine.js  (Module B)
   16 deterministic lexical/structural features (Random-Forest
   style weighted decision ensemble) + REAL live network telemetry:
     • Google Public DNS-over-HTTPS  (A / MX / TXT / DMARC)
     • RDAP domain-registration age (rdap.org)
     • Optional Google Safe Browsing threat lookup
   ============================================================ */
(function () {
  'use strict';

  const SUSPICIOUS_TLDS = ['xyz', 'top', 'click', 'zip', 'tk', 'buzz', 'loan', 'work', 'gq', 'ml', 'cf', 'country', 'stream', 'download', 'racing', 'win', 'bid', 'date', 'faith', 'review', 'party', 'cricket', 'science', 'accountant', 'men', 'surf', 'rest', 'bar'];
  const SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'rb.gy', 'is.gd', 'cutt.ly', 'shorturl.at', 'tiny.cc', 'ow.ly', 'buff.ly', 'rebrand.ly', 'tiny.one'];
  const TRUSTED = ['github.com', 'gitlab.com', 'stripe.com', 'google.com', 'google.co.in', 'microsoft.com', 'apple.com', 'amazon.com', 'amazon.in', 'hdfcbank.com', 'icicibank.com', 'sbi.co.in', 'axisbank.com', 'kotak.com', 'paypal.com', 'linkedin.com', 'zoom.us', 'slack.com', 'notion.so', 'npmjs.com', 'mozilla.org', 'wikipedia.org', 'cloudflare.com', 'vercel.com', 'supabase.com', 'gov.in', 'nic.in', 'irctc.co.in', 'uidai.gov.in'];
  const BRANDS = ['paypal', 'microsoft', 'google', 'apple', 'amazon', 'netflix', 'facebook', 'instagram', 'whatsapp', 'hdfcbank', 'hdfc', 'icicibank', 'icici', 'sbi', 'axis', 'kotak', 'flipkart', 'myntra', 'swiggy', 'zomato', 'irctc', 'binance', 'coinbase', 'metamask', 'stripe', 'linkedin', 'dropbox', 'adobe', 'dhl', 'fedex', 'indiapost', 'ups', 'sbiyono'];
  const MULTI_SUFFIXES = ['co.in', 'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'co.jp', 'co.nz', 'com.br', 'com.mx', 'com.sg', 'com.my', 'co.za', 'co.ke', 'com.pk', 'gov.in', 'nic.in', 'co.id', 'com.tr', 'com.cn', 'com.hk', 'co.kr'];

  const esc = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

  /* ---------------- Punycode (RFC 3492) decoder ---------------- */
  function punycodeDecode(input) {
    const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700, initialBias = 72, initialN = 128;
    const output = [];
    let n = initialN, i = 0, bias = initialBias;
    const delim = input.lastIndexOf('-');
    let idx = 0;
    if (delim > 0) {
      for (let j = 0; j < delim; j++) output.push(input.charCodeAt(j));
      idx = delim + 1;
    }
    const digitOf = (c) => {
      const code = c.charCodeAt(0);
      if (code >= 48 && code <= 57) return code - 22;
      if (code >= 65 && code <= 90) return code - 65;
      if (code >= 97 && code <= 122) return code - 97;
      return base;
    };
    const adapt = (delta, numPoints, firstTime) => {
      delta = firstTime ? Math.floor(delta / damp) : delta >> 1;
      delta += Math.floor(delta / numPoints);
      let k = 0;
      while (delta > ((base - tMin) * tMax) >> 1) { delta = Math.floor(delta / (base - tMin)); k += base; }
      return Math.floor(k + ((base - tMin + 1) * delta) / (delta + skew));
    };
    while (idx < input.length) {
      const oldi = i;
      let w = 1, k = base;
      for (;;) {
        if (idx >= input.length) throw new Error('malformed punycode');
        const d = digitOf(input[idx++]);
        if (d >= base) throw new Error('invalid digit');
        i += d * w;
        const t = k <= bias ? tMin : (k >= bias + tMax ? tMax : k - bias);
        if (d < t) break;
        w *= base - t;
        k += base;
      }
      const outLen = output.length + 1;
      bias = adapt(i - oldi, outLen, oldi === 0);
      n += Math.floor(i / outLen);
      i = i % outLen;
      output.splice(i, 0, n);
      i++;
    }
    return String.fromCodePoint.apply(null, output);
  }

  const HOMOGLYPHS = { 'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ї': 'i', 'ѕ': 's', 'ԁ': 'd', 'ɡ': 'g', 'ӏ': 'l', 'ο': 'o', 'α': 'a', 'ν': 'v', 'ι': 'i', 'κ': 'k', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'η': 'n', 'ｌ': 'l', 'ａ': 'a', 'ｅ': 'e', 'ⅼ': 'l', 'ⅰ': 'i', '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a' };
  const normalize = s => String(s).toLowerCase().split('').map(ch => HOMOGLYPHS[ch] || ch).join('');

  function levenshtein(a, b) {
    a = String(a); b = String(b);
    if (a === b) return 0;
    if (!a.length) return b.length;
    if (!b.length) return a.length;
    let prev = new Array(b.length + 1);
    for (let j = 0; j <= b.length; j++) prev[j] = j;
    for (let i = 1; i <= a.length; i++) {
      const cur = [i];
      for (let j = 1; j <= b.length; j++) {
        cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      }
      prev = cur;
    }
    return prev[b.length];
  }

  /* Real Shannon entropy over the hostname characters */
  function shannonEntropy(str) {
    if (!str) return 0;
    const freq = {};
    for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
    const len = str.length;
    let h = 0;
    Object.values(freq).forEach(c => { const p = c / len; h -= p * Math.log2(p); });
    return Math.round(h * 100) / 100;
  }

  function registrableDomain(host) {
    if (isIPHost(String(host).replace(/^\[|\]$/g, ''))) return String(host).replace(/^\[|\]$/g, '');
    const labels = String(host).toLowerCase().replace(/\.$/, '').split('.');
    if (labels.length <= 2) return labels.join('.');
    const last2 = labels.slice(-2).join('.');
    const last3 = labels.slice(-3).join('.');
    if (MULTI_SUFFIXES.includes(last2) && labels.length >= 3) return last3;
    return last2;
  }

  function decodeHost(host) {
    try {
      return host.split('.').map(label => {
        if (/^xn--/i.test(label)) {
          try { return punycodeDecode(label.slice(4)); } catch (e) { return label; }
        }
        return label;
      }).join('.');
    } catch (e) { return host; }
  }

  function isIPHost(host) {
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(host) || /^\[?[a-f0-9:]+\]?$/i.test(host);
  }

  function isTrustedHost(host) {
    return TRUSTED.some(d => host === d || host.endsWith('.' + d));
  }

  /* ---------------- Anatomy ---------------- */
  function extractAnatomy(raw) {
    const input = String(raw || '').trim();
    if (!input) return null;
    let candidate = input;
    let implied = false;
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(candidate)) {
      candidate = 'http://' + candidate;
      implied = true;
    }
    let u;
    try { u = new URL(candidate); } catch (e) { return null; }
    if (!u.hostname || u.hostname.indexOf('.') === -1 && !isIPHost(u.hostname) && u.hostname !== 'localhost') return null;
    const host = u.hostname.toLowerCase().replace(/\.$/, '');
    const root = registrableDomain(host);
    const rootIndex = host.lastIndexOf(root);
    const sub = rootIndex > 0 ? host.slice(0, rootIndex - 1) : '';
    const ip = isIPHost(host);
    return {
      full: u.href,
      raw: input,
      protocol: implied ? 'http (implied)' : u.protocol.replace(':', ''),
      scheme: u.protocol.replace(':', ''),
      hostname: host,
      subdomain: sub,
      rootDomain: root,
      rootLabel: root.split('.')[0],
      tld: ip ? '' : host.split('.').pop(),
      path: u.pathname,
      query: u.search,
      hash: u.hash,
      port: u.port,
      isIP: ip,
      decodedHost: decodeHost(host),
      trusted: isTrustedHost(host)
    };
  }

  /* ---------------- Feature engineering ---------------- */
  function brandImpersonationInfo(anatomy) {
    const host = anatomy.hostname;
    const root = anatomy.rootDomain;
    const rootFlat = normalize(root.split('.')[0].replace(/[^a-z0-9]/g, ''));
    const decodedRoot = decodeHost(root);
    const decodedFlat = normalize(decodedRoot.split('.')[0].replace(/[^a-z0-9]/g, ''));
    const path = (anatomy.path + anatomy.query).toLowerCase();
    const sub = anatomy.subdomain.toLowerCase();

    /* Exact trusted brand root = legitimate */
    for (const brand of BRANDS) {
      if (rootFlat === brand || decodedFlat === brand) return { hit: false, brand: brand, detail: `Root domain matches ${brand} exactly.` };
    }

    /* Homoglyph / punycode homograph */
    if (/xn--/i.test(host)) {
      for (const brand of BRANDS) {
        if (decodedFlat === brand || levenshtein(decodedFlat, brand) <= 1) {
          return { hit: true, brand, detail: `"${anatomy.decodedHost}" decodes to the brand "${brand}" — a homoglyph impersonation served from ${host}.`, homoglyph: true };
        }
      }
    }

    /* Typosquat in root */
    for (const brand of BRANDS) {
      if (brand.length < 5) continue;
      const d = levenshtein(rootFlat, brand);
      if (rootFlat !== brand && d > 0 && d <= 2) {
        return { hit: true, brand, detail: `Root "${rootFlat}" is ${d} edit(s) from brand "${brand}".`, typosquat: true };
      }
    }

    /* Brand welded onto extra words inside the root (hdfc-kyc-verify, paypal-secure-login) */
    for (const brand of BRANDS) {
      if (brand.length < 4) continue;
      if (rootFlat !== brand && rootFlat.includes(brand) && !isTrustedHost(host)) {
        return { hit: true, brand, detail: `Brand "${brand}" embedded in root "${anatomy.rootDomain}" alongside extra words.`, embedded: true };
      }
    }

    /* Brand pushed into subdomain or path while the root belongs to someone else */
    for (const brand of BRANDS) {
      if (brand.length < 5) continue;
      if ((sub.includes(brand) || path.includes(brand)) && !rootFlat.includes(brand) && !isTrustedHost(host)) {
        return { hit: true, brand, detail: `Brand "${brand}" appears in the ${sub.includes(brand) ? 'subdomain' : 'path'} but the real root domain is "${root}" — classic subdomain chaining.`, chained: true };
      }
    }
    return { hit: false, brand: null, detail: 'No brand impersonation pattern detected.' };
  }

  function buildFeatures(urlString, anatomy) {
    const u = anatomy;
    const host = u.hostname;
    const url = String(urlString);
    const digits = (url.match(/\d/g) || []).length;
    const letters = (url.match(/[a-z]/gi) || []).length;
    const digitRatio = letters + digits ? digits / (letters + digits) : 0;
    const entropy = shannonEntropy(host);
    const hostHyphens = (host.match(/-/g) || []).length;
    const atSymbols = (url.match(/@/g) || []).length;
    const dots = (host.match(/\./g) || []).length;
    const params = (() => { try { return Array.from(new URL(u.full).searchParams.keys()).length; } catch (e) { return (u.query.match(/[?&][^=&]+/g) || []).length; } })();
    const brand = brandImpersonationInfo(u);
    const tld = u.isIP ? '' : host.split('.').pop();
    const isShort = SHORTENERS.includes(registrableDomain(host));

    const defs = [
      {
        key: 'url_length', label: 'URL length', value: url.length, threshold: '> 75 chars', weight: 8,
        display: url.length + ' chars',
        risk: url.length > 120 ? 8 : url.length > 90 ? 6 : url.length > 75 ? 4 : url.length > 55 ? 1 : 0,
        why: 'Long URLs hide the real destination far to the right of the address bar.'
      },
      {
        key: 'hostname_length', label: 'Hostname length', value: host.length, threshold: '> 25 chars', weight: 6,
        display: host.length + ' chars',
        risk: host.length > 45 ? 6 : host.length > 32 ? 4 : host.length > 25 ? 2 : 0,
        why: 'Long hostnames are used to push the brand far from the visible end.'
      },
      {
        key: 'path_length', label: 'Path length', value: u.path.length, threshold: '> 40 chars', weight: 4,
        display: u.path.length + ' chars',
        risk: u.path.length > 80 ? 4 : u.path.length > 55 ? 2 : u.path.length > 40 ? 1 : 0,
        why: 'Deep, noisy paths mimic real banking portals.'
      },
      {
        key: 'shannon_entropy', label: 'Shannon entropy (host)', value: entropy, threshold: '> 3.7 bits', weight: 8,
        display: entropy.toFixed(2) + ' bits',
        risk: entropy > 4.3 ? 8 : entropy > 3.9 ? 5 : entropy > 3.55 ? 2 : 0,
        why: 'High character entropy signals machine-generated / DGA-style hostnames.'
      },
      {
        key: 'num_dots', label: 'Dot count (host)', value: dots, threshold: '≥ 3 dots', weight: 6,
        display: dots + ' dots',
        risk: dots >= 4 ? 6 : dots === 3 ? 4 : 0,
        why: 'Subdomain chaining (login.bank.com.evil.top) pushes the real domain out of view.'
      },
      {
        key: 'num_hyphens', label: 'Hyphens (host)', value: hostHyphens, threshold: '≥ 1 hyphen', weight: 6,
        display: hostHyphens + ' hyphens',
        risk: hostHyphens >= 3 ? 6 : hostHyphens === 2 ? 4 : hostHyphens === 1 ? 2 : 0,
        why: 'Hyphenated lookalikes (secure-login-bank) are a cheap typosquat technique.'
      },
      {
        key: 'num_at_symbols', label: '@ symbols in URL', value: atSymbols, threshold: '> 0', weight: 10,
        display: atSymbols + ' @',
        risk: atSymbols > 0 ? 10 : 0,
        why: 'Everything before @ is userinfo — attackers hide the true host after it.'
      },
      {
        key: 'num_digits', label: 'Digit count', value: digits, threshold: '> 3 digits', weight: 4,
        display: digits + ' digits',
        risk: digits > 8 ? 4 : digits > 4 ? 2 : 0,
        why: 'Auto-generated infrastructure often carries digit runs.'
      },
      {
        key: 'digit_letter_ratio', label: 'Digit : letter ratio', value: Math.round(digitRatio * 100) / 100, threshold: '> 0.25', weight: 4,
        display: (digitRatio * 100).toFixed(0) + '%',
        risk: digitRatio > 0.35 ? 4 : digitRatio > 0.25 ? 2 : 0,
        why: 'High digit density correlates with disposable hostnames.'
      },
      {
        key: 'has_ip_address', label: 'Raw IP host', value: u.isIP ? 1 : 0, threshold: '0 expected', weight: 18,
        display: u.isIP ? 'YES — ' + host : 'no',
        risk: u.isIP ? 18 : 0,
        why: 'No legitimate bank, brand or government portal links to a bare IP address.'
      },
      {
        key: 'is_https', label: 'HTTPS transport', value: u.scheme === 'https' ? 1 : 0, threshold: 'must be 1', weight: 3,
        display: u.scheme === 'https' ? 'encrypted' : u.scheme,
        risk: u.scheme === 'https' ? 0 : 3,
        why: 'Plain HTTP exposes the page and is still common on throw-away phishing hosts.'
      },
      {
        key: 'has_punycode', label: 'Punycode label (xn--)', value: /xn--/i.test(host) ? 1 : 0, threshold: '0 expected', weight: 16,
        display: /xn--/i.test(host) ? 'YES → ' + u.decodedHost : 'no',
        risk: /xn--/i.test(host) ? 16 : 0,
        why: 'Punycode enables Cyrillic/Greek homoglyphs that render as a perfect brand name.'
      },
      {
        key: 'suspicious_tld', label: 'Suspicious TLD', value: SUSPICIOUS_TLDS.includes(tld) ? 1 : 0, threshold: 'not in blocklist', weight: 14,
        display: tld ? '.' + tld : 'n/a',
        risk: SUSPICIOUS_TLDS.includes(tld) ? 14 : 0,
        why: '.xyz/.top/.click/.zip are cheap bulk-registered and heavily abused.'
      },
      {
        key: 'is_url_shortener', label: 'URL shortener', value: isShort ? 1 : 0, threshold: '0 expected', weight: 8,
        display: isShort ? registrableDomain(host) : 'no',
        risk: isShort ? 8 : 0,
        why: 'Shorteners hide the final destination from the reader and from filters.'
      },
      {
        key: 'brand_impersonation', label: 'Brand impersonation', value: brand.hit ? 1 : 0, threshold: '0 expected', weight: 14,
        display: brand.hit ? brand.brand.toUpperCase() + ' lookalike' : 'none',
        risk: brand.hit ? 14 : 0,
        why: brand.detail
      },
      {
        key: 'query_param_count', label: 'Query parameters', value: params, threshold: '≤ 2 params', weight: 4,
        display: params + ' params',
        risk: params >= 4 ? 4 : params === 3 ? 2 : 0,
        why: 'Campaign/token-heavy query strings are typical of credential-harvest redirects.'
      }
    ];

    return defs.map(f => ({
      key: f.key, label: f.label, value: f.value, display: f.display,
      threshold: f.threshold, weight: f.weight, riskContribution: f.risk,
      status: f.risk === 0 ? 'good' : f.risk >= 8 ? 'bad' : 'warn',
      explanation: f.why
    }));
  }

  /* ---------------- Local (offline) scoring ---------------- */
  function analyze(raw) {
    const anatomy = extractAnatomy(raw);
    if (!anatomy) {
      return { valid: false, url: String(raw || ''), score: 0, features: [], anatomy: null, error: 'That does not look like a URL or domain.', riskLevel: 'unknown', evidence: [] };
    }
    const features = buildFeatures(anatomy.full, anatomy);
    const totalRisk = features.reduce((s, f) => s + f.riskContribution, 0);
    const maxRisk = features.reduce((s, f) => s + f.weight, 0);
    let score = 100 * (1 - Math.exp(-totalRisk / 26));
    const brand = brandImpersonationInfo(anatomy);

    /* Trusted domains get a strong, explicit discount */
    if (anatomy.trusted) score -= 18;
    /* A clean HTTPS root on a plain 2-label domain with no risk: floor to 0 */
    if (totalRisk === 0) score = 0;
    score = Math.max(0, Math.min(100, Math.round(score)));

    const riskLevel = score >= 65 ? 'critical' : score >= 35 ? 'elevated' : score >= 15 ? 'guarded' : 'low';

    const evidence = [];
    features.filter(f => f.riskContribution > 0).sort((a, b) => b.riskContribution - a.riskContribution).forEach(f => {
      evidence.push({ tone: f.riskContribution >= 8 ? 'danger' : 'warn', text: `${f.label}: ${f.display} — ${f.explanation}` });
    });
    if (anatomy.trusted) evidence.push({ tone: 'safe', text: `${anatomy.rootDomain} is on the trusted-domain allowlist (verified brand root).` });
    if (brand.hit) evidence.push({ tone: 'danger', text: brand.detail });
    if (!evidence.length) evidence.push({ tone: 'safe', text: 'All 16 structural features are inside their safe thresholds.' });

    return {
      valid: true,
      engine: 'url-rf-16',
      url: anatomy.full,
      input: String(raw),
      normalizedUrl: anatomy.full,
      score,
      localScore: score,
      riskLevel,
      anatomy,
      features,
      evidence,
      trustedHost: anatomy.trusted,
      brand: brand.hit ? brand : null,
      maxRisk,
      totalRisk,
      live: { status: 'idle' },
      safeBrowsing: { status: 'not-checked' },
      randomForest: { features: features.length, weightedRisk: totalRisk, ceiling: maxRisk }
    };
  }

  /* ---------------- LIVE: Google DNS-over-HTTPS ---------------- */
  async function dohQuery(name, type, timeout) {
    const url = 'https://dns.google/resolve?name=' + encodeURIComponent(name) + '&type=' + encodeURIComponent(type);
    const json = await window.XRUtil.fetchJSON(url, null, timeout || 7000);
    return json;
  }

  async function lookupDNS(host) {
    const out = { host, status: 'ok', records: {}, error: null, timings: {} };
    const started = performance.now();
    try {
      const [a, mx, txt] = await Promise.all([
        dohQuery(host, 'A').catch(e => ({ error: e.message })),
        dohQuery(host, 'MX').catch(e => ({ error: e.message })),
        dohQuery(host, 'TXT').catch(e => ({ error: e.message }))
      ]);
      let dmarc = { error: 'not queried' };
      try { dmarc = await dohQuery('_dmarc.' + host, 'TXT', 6000); } catch (e) { dmarc = { error: e.message }; }

      out.records.A = a;
      out.records.MX = mx;
      out.records.TXT = txt;
      out.records.DMARC = dmarc;

      const statusOf = r => (r && typeof r.Status === 'number') ? r.Status : null;
      const answersOf = r => (r && Array.isArray(r.Answer)) ? r.Answer : [];
      out.status = statusOf(a) === 3 ? 'nxdomain' : statusOf(a) === 0 ? 'ok' : statusOf(a) !== null ? 'error' : 'unreachable';
      out.aRecords = answersOf(a).filter(x => x.type === 1).map(x => x.data);
      out.cnameRecords = answersOf(a).filter(x => x.type === 5).map(x => x.data);
      out.mxRecords = answersOf(mx).filter(x => x.type === 15).map(x => ({ priority: x.data.split(' ')[0], exchange: x.data.split(' ')[1] || x.data }));
      const txtAll = answersOf(txt).filter(x => x.type === 16).map(x => String(x.data).replace(/^"|"$/g, ''));
      out.spf = txtAll.find(t => /v=spf1/i.test(t)) || null;
      const dmarcTxt = answersOf(dmarc).filter(x => x.type === 16).map(x => String(x.data).replace(/^"|"$/g, ''));
      out.dmarc = dmarcTxt.find(t => /v=DMARC1/i.test(t)) || null;
      out.resolves = out.aRecords.length > 0 || out.cnameRecords.length > 0;
      out.hasMX = out.mxRecords.length > 0;
      out.hasSPF = !!out.spf;
      out.hasDMARC = !!out.dmarc;
      out.latencyMs = Math.round(performance.now() - started);
      return out;
    } catch (err) {
      out.status = 'unreachable';
      out.error = err.message || String(err);
      out.latencyMs = Math.round(performance.now() - started);
      return out;
    }
  }

  /* ---------------- LIVE: RDAP domain age ---------------- */
  async function lookupRDAP(domain) {
    const out = { domain, status: 'unknown', ageDays: null, registered: null, expiry: null, registrar: null, error: null };
    const started = performance.now();
    try {
      let json;
      try {
        json = await window.XRUtil.fetchJSON('https://rdap.org/domain/' + encodeURIComponent(domain), null, 9000);
      } catch (httpErr) {
        if (/404/.test(String(httpErr.message))) {
          out.status = 'not-found';
          out.error = 'No RDAP registration record exists for ' + domain + '.';
          out.latencyMs = Math.round(performance.now() - started);
          return out;
        }
        throw httpErr;
      }
      out.rawStatus = json.status || [];
      if (Array.isArray(json.events)) {
        const reg = json.events.find(e => /registration/i.test(e.eventAction));
        const exp = json.events.find(e => /expiration/i.test(e.eventAction));
        if (reg && reg.eventDate) {
          out.registered = reg.eventDate;
          const regDate = new Date(reg.eventDate);
          const days = Math.floor((Date.now() - regDate.getTime()) / 86400000);
          out.ageDays = days;
          out.ageYears = Math.round((days / 365) * 10) / 10;
          out.status = 'ok';
        }
        if (exp && exp.eventDate) out.expiry = exp.eventDate;
      }
      if (Array.isArray(json.entities)) {
        const registrarEntity = json.entities.find(e => (e.roles || []).includes('registrar'));
        if (registrarEntity) {
          const vcard = (registrarEntity.vcardArray && registrarEntity.vcardArray[1]) || [];
          const fn = vcard.find(v => v[0] === 'fn');
          out.registrar = fn ? fn[3] : (registrarEntity.handle || null);
        }
      }
      if (out.status !== 'ok') out.status = 'partial';
      out.latencyMs = Math.round(performance.now() - started);
      return out;
    } catch (err) {
      out.status = 'unavailable';
      out.error = err.message || String(err);
      out.latencyMs = Math.round(performance.now() - started);
      return out;
    }
  }

  /* ---------------- Optional Google Safe Browsing ---------------- */
  async function checkSafeBrowsing(url) {
    let key = '';
    try { key = window.XRUtil.getApiKeys().safeBrowsing; } catch (e) { key = ''; }
    if (!key) return { status: 'not-configured', message: 'Add a Safe Browsing key in the API modal to enable.' };
    try {
      const body = {
        client: { clientId: 'catalyst-shield', clientVersion: '2.0.0' },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }]
        }
      };
      const res = await fetch('https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' + encodeURIComponent(key), {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
      });
      if (!res.ok) {
        const txt = await res.text();
        return { status: 'error', message: 'Safe Browsing HTTP ' + res.status + ' — ' + txt.slice(0, 120) };
      }
      const json = await res.json();
      const matches = json.matches || [];
      return matches.length
        ? { status: 'threat', matches: matches.map(m => ({ type: m.threatType, url: m.threat && m.threat.url })) }
        : { status: 'clean', message: 'No Safe Browsing match.' };
    } catch (e) {
      return { status: 'error', message: e.message };
    }
  }

  /* ---------------- Live verification & merge ---------------- */
  async function verifyLive(anatomy, onStage) {
    const host = anatomy.hostname;
    const domain = anatomy.rootDomain;
    const notify = typeof onStage === 'function' ? onStage : () => {};

    if (anatomy.isIP) {
      const dns = await lookupDNS(host);
      return {
        status: 'complete', dns, rdap: { status: 'skipped', message: 'IP hosts have no RDAP registration record.' },
        flags: [], penalty: 0, evidence: []
      };
    }

    notify('dns');
    const dnsP = lookupDNS(domain);
    notify('rdap');
    const rdapP = lookupRDAP(domain);
    const [dns, rdap] = await Promise.all([dnsP, rdapP]);

    const flags = [];
    let penalty = 0;

    if (dns.status === 'nxdomain') {
      flags.push({ id: 'dns-nxdomain', tone: 'danger', label: 'Domain does not resolve', detail: `${domain} returns NXDOMAIN from Google Public DNS — the domain does not exist.` });
      penalty += 16;
    } else if (dns.status === 'unreachable' || dns.status === 'error') {
      flags.push({ id: 'dns-offline', tone: 'warn', label: 'DNS lookup unavailable', detail: 'Google DoH could not be reached from this browser; structural analysis still applies.' });
    } else {
      if (!dns.resolves && !dns.hasMX) {
        flags.push({ id: 'dns-no-a', tone: 'danger', label: 'No A / MX records', detail: `${domain} resolves to no address and accepts no mail — dead or fabricated infrastructure.` });
        penalty += 10;
      } else if (!dns.resolves) {
        flags.push({ id: 'dns-no-a', tone: 'warn', label: 'No A record', detail: `${domain} has no web address (A record).` });
        penalty += 5;
      } else {
        flags.push({ id: 'dns-ok', tone: 'safe', label: 'Domain resolves', detail: `${dns.aRecords.length} A record(s): ${dns.aRecords.slice(0, 3).join(', ') || dns.cnameRecords[0] || 'via CNAME'}` });
      }
      if (!dns.hasMX) {
        flags.push({ id: 'dns-no-mx', tone: 'warn', label: 'No MX record', detail: `${domain} cannot receive email — inconsistent for a bank/company domain.` });
        penalty += 2;
      } else {
        flags.push({ id: 'dns-mx', tone: 'info', label: 'Mail exchanger present', detail: `${dns.mxRecords.length} MX record(s), first: ${dns.mxRecords[0].exchange}` });
      }
      if (!dns.hasSPF) {
        flags.push({ id: 'dns-no-spf', tone: 'warn', label: 'No SPF record', detail: 'No v=spf1 TXT record — the domain cannot protect its own sender identity.' });
        penalty += 2;
      } else {
        flags.push({ id: 'dns-spf', tone: 'safe', label: 'SPF configured', detail: dns.spf });
      }
      if (!dns.hasDMARC) {
        flags.push({ id: 'dns-no-dmarc', tone: 'warn', label: 'No DMARC record', detail: 'No v=DMARC1 policy — spoofed mail from this domain is not rejected.' });
        penalty += 2;
      } else {
        flags.push({ id: 'dns-dmarc', tone: 'safe', label: 'DMARC policy found', detail: dns.dmarc });
      }
    }

    if (rdap.status === 'ok' && typeof rdap.ageDays === 'number') {
      if (rdap.ageDays < 30) {
        flags.push({ id: 'rdap-new', tone: 'danger', label: 'Domain registered ' + rdap.ageDays + ' days ago', detail: `Registered ${rdap.registered} (${rdap.ageDays} days). Phishing infrastructure is overwhelmingly younger than 30 days.` });
        penalty += 18;
      } else if (rdap.ageDays < 90) {
        flags.push({ id: 'rdap-young', tone: 'warn', label: 'Domain is ' + rdap.ageDays + ' days old', detail: `Registered ${rdap.registered}. Newly registered domains carry elevated risk.` });
        penalty += 9;
      } else if (rdap.ageDays < 365) {
        flags.push({ id: 'rdap-recent', tone: 'warn', label: 'Domain under 1 year old', detail: `Registered ${rdap.registered} (${rdap.ageDays} days).` });
        penalty += 3;
      } else {
        flags.push({ id: 'rdap-old', tone: 'safe', label: 'Established domain', detail: `Registered ${new Date(rdap.registered).toISOString().slice(0, 10)} — ${rdap.ageYears} years of history.` });
      }
    } else if (rdap.status === 'not-found') {
      flags.push({ id: 'rdap-unregistered', tone: 'danger', label: 'No RDAP registration record', detail: `${domain} has no registration record — the domain is not registered, so any link to it is dead or fabricated.` });
      penalty += 14;
    } else if (rdap.status === 'unavailable') {
      flags.push({ id: 'rdap-unavailable', tone: 'warn', label: 'RDAP unavailable', detail: 'Registration data could not be fetched (registry CORS/timeout). Structural score only.' });
    }

    const evidence = flags.filter(f => f.tone === 'danger' || f.tone === 'warn').map(f => ({ tone: f.tone, text: `${f.label}: ${f.detail}` }));
    return { status: 'complete', dns, rdap, flags, penalty, evidence };
  }

  function mergeLive(local, live, safeBrowsing) {
    if (!live || live.status !== 'complete') return local;
    let score = local.localScore + live.penalty;
    const flags = live.flags || [];

    /* Well-established, correctly authenticated domain gets a mild trust credit */
    const established = flags.some(f => f.id === 'rdap-old');
    const mailAuth = flags.some(f => f.id === 'dns-spf') && flags.some(f => f.id === 'dns-dmarc');
    if (established && mailAuth && !local.brand) score -= 6;
    if (live.dns && live.dns.latencyMs) score = Math.max(0, Math.round(score));

    if (safeBrowsing && safeBrowsing.status === 'threat') score = 100;

    score = Math.max(0, Math.min(100, Math.round(score)));

    const evidence = [].concat(
      (live.evidence || []).map(e => ({ tone: e.tone, text: e.text })),
      local.evidence
    );
    if (safeBrowsing && safeBrowsing.status === 'threat') {
      evidence.unshift({ tone: 'danger', text: 'Google Safe Browsing reports an active ' + safeBrowsing.matches.map(m => m.type).join(', ') + ' threat on this URL.' });
    }

    return Object.assign({}, local, {
      score,
      riskLevel: score >= 65 ? 'critical' : score >= 35 ? 'elevated' : score >= 15 ? 'guarded' : 'low',
      evidence,
      live,
      safeBrowsing: safeBrowsing || local.safeBrowsing
    });
  }

  async function analyzeUrlFull(raw, opts) {
    opts = opts || {};
    const local = analyze(raw);
    if (!local.valid) return local;
    if (opts.includeLive === false) return local;

    const sbP = checkSafeBrowsing(local.url);
    let live;
    try {
      live = await verifyLive(local.anatomy, opts.onStage);
    } catch (e) {
      live = { status: 'complete', flags: [{ id: 'live-fail', tone: 'warn', label: 'Live lookup failed', detail: e.message }], penalty: 0, evidence: [], dns: null, rdap: null };
    }
    let sb;
    try { sb = await sbP; } catch (e) { sb = { status: 'error', message: e.message }; }
    return mergeLive(local, live, sb);
  }

  /* Public API */
  window.URLBrain = {
    analyze,
    analyzeUrlFull,
    extractAnatomy,
    verifyLive,
    lookupDNS,
    lookupRDAP,
    checkSafeBrowsing,
    shannonEntropy,
    punycodeDecode,
    registrableDomain,
    buildFeatures,
    SUSPICIOUS_TLDS,
    TRUSTED
  };
  window.analyzeUrlRandomForest = function (urlString) { return analyze(urlString); };
})();
