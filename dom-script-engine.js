/* ============================================================
   XEROX — dom-script-engine.js  (Module C)
   Real HTML / JavaScript inspector for credential harvesters,
   obfuscated payloads, hidden iframes, anti-inspection hooks,
   clipboard hijacks and exfiltration channels.
   ============================================================ */
(function () {
  'use strict';

  const esc = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');

  const IPS = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;

  function lineOfIndex(text, index) {
    let line = 1;
    for (let i = 0; i < index && i < text.length; i++) if (text[i] === '\n') line++;
    return line;
  }

  /* ------------------------------------------------------------
     Detection catalogue
     Each detector returns 0..2 findings.
     ------------------------------------------------------------ */
  function detectForms(html, add) {
    const formRe = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
    let m;
    while ((m = formRe.exec(html)) !== null) {
      const attrs = m[1] || '';
      const inner = m[2] || '';
      const actionMatch = attrs.match(/\baction\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))/i);
      const action = actionMatch ? (actionMatch[2] || actionMatch[3] || actionMatch[4] || '') : '';
      const hasPassword = /<input\b[^>]*type\s*=\s*["']?password/i.test(inner);
      const hasCredWords = /(pass(word|code)|pin|cvv|card|otp|user(name)?|login|seed|mnemonic)/i.test(inner);
      const line = lineOfIndex(html, m.index);

      if (hasPassword) {
        add({
          id: 'form-password', severity: 'medium', weight: 6, line,
          label: 'Password field present',
          detail: 'The page contains a <input type="password"> field — credential entry surface.',
          snippet: '<form ...> … <input type="password"> … </form>'
        });
      }

      if (action && !/^(#|\/|\.\/|\?|javascript:void)/i.test(action)) {
        const isHttp = /^http:\/\//i.test(action);
        const isIp = IPS.test(action.replace(/^https?:\/\//, '').split('/')[0]);
        const isTelegram = /api\.telegram\.org|discord\.com\/api\/webhooks/i.test(action);
        if (isTelegram) {
          add({
            id: 'form-telegram-exfil', severity: 'critical', weight: 22, line,
            label: 'Form posts to a chat-bot webhook',
            detail: 'Credentials are being sent straight into a Telegram/Discord bot — a live exfiltration channel.',
            snippet: 'action="' + action + '"'
          });
        } else if (isIp) {
          add({
            id: 'form-ip-exfil', severity: 'critical', weight: 20, line,
            label: 'Form posts to a raw IP',
            detail: 'The form action is a bare IP address (' + action + '). No legitimate bank submits credentials to an IP.',
            snippet: 'action="' + action + '"'
          });
        } else if (isHttp) {
          add({
            id: 'form-http-exfil', severity: 'critical', weight: 16, line,
            label: 'Form posts over plain HTTP',
            detail: 'Credentials would travel unencrypted to ' + action + '.',
            snippet: 'action="' + action + '"'
          });
        } else if (hasPassword || hasCredWords) {
          add({
            id: 'form-external', severity: 'high', weight: 13, line,
            label: 'Credential form posts off-site',
            detail: 'The credential form submits to an external destination (' + action + ') instead of the page origin.',
            snippet: 'action="' + action + '"'
          });
        }
      }

      /* JS-driven submission with no action attribute */
      if (!action && hasPassword && /(submit\(\)|document\.forms|addEventListener\(['"]submit)/i.test(html)) {
        add({
          id: 'form-js-submit', severity: 'high', weight: 10, line,
          label: 'Credential form captured by script',
          detail: 'The password form has no action and is intercepted by JavaScript — typically posted to an attacker endpoint.',
          snippet: '<form id="loginform"> … JS submit handler'
        });
      }
    }

    const loosePassword = /<input\b[^>]*type\s*=\s*["']?password/i.exec(html);
    const hasAnyForm = /<form\b/i.test(html);
    if (loosePassword && !hasAnyForm) {
      add({
        id: 'input-password-loose', severity: 'medium', weight: 6, line: lineOfIndex(html, loosePassword.index),
        label: 'Unscoped password input',
        detail: 'A password input exists outside a well-formed form — a common pattern in injected overlays.',
        snippet: loosePassword[0]
      });
    }
  }

  function detectObfuscation(html, add) {
    const patterns = [
      { id: 'js-eval', re: /\beval\s*\(/gi, weight: 14, severity: 'critical', label: 'eval() execution', detail: 'eval() turns a string into executable code — the standard wrapper for obfuscated payloads.' },
      { id: 'js-atob', re: /\batob\s*\(/gi, weight: 11, severity: 'high', label: 'Base64 decode (atob)', detail: 'atob() decodes base64 at runtime, hiding URLs and scripts from static filters.' },
      { id: 'js-unescape', re: /\bunescape\s*\(/gi, weight: 10, severity: 'high', label: 'unescape() decoding', detail: 'Legacy percent-decoding used to reconstruct malicious strings at runtime.' },
      { id: 'js-fromcharcode', re: /String\.fromCharCode\s*\(/gi, weight: 9, severity: 'high', label: 'String.fromCharCode obfuscation', detail: 'Character-code arrays reconstruct strings without ever writing them literally.' },
      { id: 'js-docwrite', re: /\bdocument\.write(?:ln)?\s*\(/gi, weight: 7, severity: 'medium', label: 'document.write() injection', detail: 'document.write is used to inject iframes and scripts after the page loads.' },
      { id: 'js-newfunction', re: /\bnew\s+Function\s*\(/gi, weight: 12, severity: 'high', label: 'new Function() constructor', detail: 'Equivalent to eval() and equally able to hide a payload.' },
      { id: 'js-hex-array', re: /(?:0x[0-9a-f]{2}\s*,\s*){6,}/gi, weight: 10, severity: 'high', label: 'Hex-encoded byte array', detail: 'A long hex array is a decoded payload waiting to be assembled.' },
      { id: 'js-charcode-loop', re: /charCodeAt\s*\(/gi, weight: 5, severity: 'medium', label: 'Runtime character assembly', detail: 'charCodeAt() inside decoding loops can rebuild hidden strings.' },
      { id: 'js-debugger', re: /\bdebugger\s*;/g, weight: 8, severity: 'high', label: 'debugger trap', detail: 'debugger statements freeze DevTools so the victim cannot inspect the page.' }
    ];
    patterns.forEach(p => {
      const re = new RegExp(p.re.source, p.re.flags);
      let m, count = 0;
      while ((m = re.exec(html)) !== null && count < 2) {
        add({
          id: p.id, severity: p.severity, weight: p.weight, line: lineOfIndex(html, m.index),
          label: p.label, detail: p.detail, snippet: m[0]
        });
        count++;
        if (m[0].length === 0) re.lastIndex++;
      }
    });

    /* Long base64 blobs */
    const b64 = /["'`]([A-Za-z0-9+/]{120,}={0,2})["'`]/g;
    const bm = b64.exec(html);
    if (bm) {
      add({
        id: 'js-b64-blob', severity: 'high', weight: 11, line: lineOfIndex(html, bm.index),
        label: 'Large base64 blob', detail: 'A ' + bm[1].length + '-character base64 literal is almost certainly an encoded payload.',
        snippet: bm[1].slice(0, 60) + '…'
      });
    }

    /* Hex-escaped strings  */
    const hexEsc = /(?:\\x[0-9a-f]{2}){8,}/gi;
    const hm = hexEsc.exec(html);
    if (hm) {
      add({
        id: 'js-hex-string', severity: 'high', weight: 9, line: lineOfIndex(html, hm.index),
        label: 'Hex-escaped string', detail: 'Long \\x-escaped sequences hide literal text (URLs, scripts) from scanners.',
        snippet: hm[0].slice(0, 50) + '…'
      });
    }
  }

  function detectHiddenElements(html, add) {
    const tagRe = /<(iframe|embed|object|frame)\b([^>]*)>/gi;
    let m;
    while ((m = tagRe.exec(html)) !== null) {
      const tag = m[1].toLowerCase();
      const attrs = m[2] || '';
      const styleMatch = attrs.match(/style\s*=\s*("([^"]*)"|'([^']*)')/i) || [];
      const styleVal = String(styleMatch[2] || styleMatch[3] || '').toLowerCase();
      const hidden =
        /display\s*:\s*none/.test(styleVal) ||
        /opacity\s*:\s*0(?![.\d])/.test(styleVal) ||
        /visibility\s*:\s*hidden/.test(styleVal) ||
        (/left\s*:\s*-\d{3,}/.test(styleVal)) ||
        (/\bwidth\s*=\s*["']?0["']?/i.test(attrs) && /\bheight\s*=\s*["']?0["']?/i.test(attrs));
      const src = (attrs.match(/\bsrc\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))/i) || []);
      const srcVal = src[2] || src[3] || src[4] || '';
      const line = lineOfIndex(html, m.index);

      if (hidden) {
        const remote = /^https?:\/\//i.test(srcVal) || /^\/\//.test(srcVal);
        const isIp = IPS.test(srcVal.replace(/^https?:\/\//, '').split('/')[0]);
        add({
          id: 'hidden-frame', severity: 'critical', weight: 16 + (remote ? 4 : 0) + (isIp ? 4 : 0), line,
          label: 'Hidden <' + tag + '> element',
          detail: 'A zero-size / invisible ' + tag + ' is embedded' + (srcVal ? ' loading ' + srcVal : '') + '. This is used for silent tracking, clickjacking or a second-stage payload.',
          snippet: m[0].slice(0, 160)
        });
      } else if (/^https?:\/\//i.test(srcVal) && (IPS.test(srcVal.replace(/^https?:\/\//, '').split('/')[0]) || /telegram/i.test(srcVal))) {
        add({
          id: 'frame-suspicious-src', severity: 'high', weight: 10, line,
          label: 'Frame from suspicious origin',
          detail: '<' + tag + '> loads ' + srcVal + ' — an IP / bot endpoint rather than a normal content host.',
          snippet: m[0].slice(0, 160)
        });
      }
    }

    /* CSS-hidden divs/forms containing password inputs */
    const hiddenCssBlocks = /style\s*=\s*("|')([^"']*(?:display\s*:\s*none|opacity\s*:\s*0|left\s*:\s*-\d{3,}|position\s*:\s*absolute;\s*top\s*:\s*-\d{3,})[^"']*)\1/gi;
    if (hiddenCssBlocks.test(html) && /type\s*=\s*["']?password/i.test(html)) {
      add({
        id: 'hidden-credential-overlay', severity: 'high', weight: 12,
        line: lineOfIndex(html, (hiddenCssBlocks.lastIndex || 0)),
        label: 'Credential UI inside hidden container',
        detail: 'A password field sits inside an element hidden by CSS — the classic invisible-login overlay.',
        snippet: 'style="display:none" … <input type="password">'
      });
    }

    /* Cloaked pixel tracking */
    const pixel = /<img\b[^>]*\b(?:width|height)\s*=\s*["']?1["']?[^>]*>/gi;
    const pm = pixel.exec(html);
    if (pm && IPS.test(pm[0])) {
      add({
        id: 'tracking-pixel', severity: 'medium', weight: 7, line: lineOfIndex(html, pm.index),
        label: 'Tracking pixel to an IP',
        detail: 'A 1×1 image beacon reports the victim\'s IP and referrer back to attacker infrastructure.',
        snippet: pm[0].slice(0, 120)
      });
    }
  }

  function detectAntiInspection(html, add) {
    const checks = [
      { id: 'ai-contextmenu', re: /oncontextmenu\s*=/gi, weight: 8, severity: 'high', label: 'Right-click disabled', detail: 'oncontextmenu handlers are injected to stop victims viewing or saving the page.' },
      { id: 'ai-f12', re: /(?:keyCode\s*===?\s*123|key\s*===?\s*["']F12["']|ctrlKey\s*&&\s*shiftKey\s*&&\s*key\s*===?\s*["']I["'])/gi, weight: 10, severity: 'high', label: 'DevTools key blocker', detail: 'The page intercepts F12 / Ctrl+Shift+I — a script that hides itself from inspection.' },
      { id: 'ai-preventdefault', re: /addEventListener\(\s*["']keydown["'][\s\S]{0,120}?preventDefault\s*\(/gi, weight: 6, severity: 'medium', label: 'Keyboard suppression', detail: 'Keydown events are cancelled, blocking shortcuts used to inspect or close the page.' },
      { id: 'ai-devdetect', re: /(?:devtools|debugger)\s*(?:detect|check|isOpen)/gi, weight: 7, severity: 'medium', label: 'DevTools detection', detail: 'Timing or dimension checks try to detect an open inspector and alter behaviour.' },
      { id: 'ai-selectnone', re: /user-select\s*:\s*none/gi, weight: 2, severity: 'low', label: 'Text selection blocked', detail: 'Copy prevention is often bundled with other anti-inspection tricks.' },
      { id: 'ai-blur', re: /onblur\s*=\s*["'][^"']*alert/gi, weight: 4, severity: 'medium', label: 'Focus trap', detail: 'Alert-on-blur patterns try to keep the victim inside the page.' }
    ];
    checks.forEach(c => {
      const m = c.re.exec(html);
      if (m) add({ id: c.id, severity: c.severity, weight: c.weight, line: lineOfIndex(html, m.index), label: c.label, detail: c.detail, snippet: m[0].slice(0, 100) });
    });
  }

  function detectExfiltration(html, add) {
    const channels = [
      { id: 'ex-telegram', re: /api\.telegram\.org|discord(?:app)?\.com\/api\/webhooks|bot[0-9]{8,}:[A-Za-z0-9_-]{20,}/gi, weight: 22, severity: 'critical', label: 'Chat-bot exfiltration endpoint', detail: 'Stolen data is pushed to a Telegram/Discord bot, which is nearly untraceable.' },
      { id: 'ex-sendbeacon', re: /navigator\.sendBeacon\s*\(/gi, weight: 9, severity: 'high', label: 'sendBeacon exfiltration', detail: 'Beacon calls silently ship page data even as the user navigates away.' },
      { id: 'ex-fetch-ip', re: /fetch\s*\(\s*["'`]https?:\/\/(?:\d{1,3}\.){3}\d{1,3}/gi, weight: 13, severity: 'high', label: 'fetch() to a raw IP', detail: 'Scripted requests to an IP endpoint bypass domain-based monitoring.' },
      { id: 'ex-xhr-ip', re: /\.open\s*\(\s*["'](?:POST|GET)["']\s*,\s*["'`]https?:\/\/(?:\d{1,3}\.){3}\d{1,3}/gi, weight: 13, severity: 'high', label: 'XHR to a raw IP', detail: 'XMLHttpRequest posts data straight to attacker infrastructure.' },
      { id: 'ex-cookie', re: /document\.cookie/gi, weight: 6, severity: 'medium', label: 'Cookie access', detail: 'Reading document.cookie can exfiltrate session identifiers.' },
      { id: 'ex-clipboard', re: /clipboard\.writeText\s*\(/gi, weight: 8, severity: 'high', label: 'Clipboard overwrite', detail: 'Clipboard hijacking swaps a copied wallet address or account number for the attacker\'s.' },
      { id: 'ex-websocket', re: /new\s+WebSocket\s*\(\s*["'`]ws:\/\//gi, weight: 6, severity: 'medium', label: 'Unencrypted WebSocket', detail: 'A ws:// channel keeps a live, unencrypted command link to the attacker.' },
      { id: 'ex-metarefresh', re: /<meta[^>]+http-equiv\s*=\s*["']?refresh[^>]*url\s*=\s*https?:\/\//gi, weight: 8, severity: 'high', label: 'Meta-refresh redirect', detail: 'The page auto-redirects to an external destination after a delay.' }
    ];
    channels.forEach(c => {
      const m = c.re.exec(html);
      if (m) add({ id: c.id, severity: c.severity, weight: c.weight, line: lineOfIndex(html, m.index), label: c.label, detail: c.detail, snippet: m[0].slice(0, 110) });
    });

    /* External <script src> from an IP or plain HTTP */
    const scriptRe = /<script\b([^>]*)>/gi;
    let m;
    while ((m = scriptRe.exec(html)) !== null) {
      const attrs = m[1] || '';
      const src = (attrs.match(/\bsrc\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))/i) || []);
      const srcVal = src[2] || src[3] || src[4] || '';
      if (!srcVal) continue;
      const hostPart = srcVal.replace(/^https?:\/\//i, '').split('/')[0];
      if (/^http:\/\//i.test(srcVal)) {
        add({
          id: 'script-http', severity: 'high', weight: 11, line: lineOfIndex(html, m.index),
          label: 'Script loaded over HTTP',
          detail: 'An external script is fetched unencrypted from ' + srcVal + ' and can be swapped in transit.',
          snippet: m[0].slice(0, 140)
        });
      } else if (IPS.test(hostPart)) {
        add({
          id: 'script-ip', severity: 'critical', weight: 14, line: lineOfIndex(html, m.index),
          label: 'Script served from an IP',
          detail: 'Remote code is loaded from a bare IP (' + srcVal + ').',
          snippet: m[0].slice(0, 140)
        });
      }
    }
  }

  function detectSocialTricks(html, add) {
    const tricks = [
      { id: 'st-dialog', re: /alert\s*\(\s*["'][^"']*(?:verify|suspend|block|security|virus|hacked)/gi, weight: 4, severity: 'low', label: 'Fear dialog', detail: 'Alert boxes stage a fake security warning.' },
      { id: 'st-fullscreen', re: /position\s*:\s*fixed\s*;\s*(?:top|inset)\s*:\s*0/gi, weight: 4, severity: 'low', label: 'Full-screen overlay', detail: 'A fixed full-screen layer is used to lock the victim into a fake login.' },
      { id: 'st-disable-nav', re: /history\.pushState|popstate|beforeunload\s*=/gi, weight: 3, severity: 'low', label: 'Navigation trap', detail: 'Back-button traps keep victims on the phishing page.' },
      { id: 'st-fake-support', re: /(?:microsoft|apple|windows)\s+(?:support|defender|security)\s+(?:alert|warning|call)/gi, weight: 5, severity: 'medium', label: 'Fake vendor support warning', detail: 'Impersonated vendor support warnings drive victims to call a scam number.' }
    ];
    tricks.forEach(c => {
      const m = c.re.exec(html);
      if (m) add({ id: c.id, severity: c.severity, weight: c.weight, line: lineOfIndex(html, m.index), label: c.label, detail: c.detail, snippet: m[0].slice(0, 110) });
    });
  }

  /* ------------------------------------------------------------
     Annotated code renderer
     ------------------------------------------------------------ */
  const TOKEN_RULES = [
    { re: /&lt;\/?(script|iframe|embed|object|form)\b/gi, cls: 'tok-tag' },
    { re: /\b(eval|atob|unescape|new\s+Function)\s*\(/g, cls: 'tok-danger' },
    { re: /\b(document\.write|String\.fromCharCode|sendBeacon)\b/g, cls: 'tok-danger' },
    { re: /\b(oncontextmenu|onkeydown|onblur|onerror|onload)\s*=/gi, cls: 'tok-warn' },
    { re: /\b(display\s*:\s*none|opacity\s*:\s*0|visibility\s*:\s*hidden)\b/gi, cls: 'tok-warn' },
    { re: /\b(width|height)\s*=\s*(&quot;|"|')?0\b/gi, cls: 'tok-warn' },
    { re: /(https?:\/\/(?:\d{1,3}\.){3}\d{1,3}[^\s"'&]*)/gi, cls: 'tok-danger' },
    { re: /(api\.telegram\.org[^\s"'&]*)/gi, cls: 'tok-danger' },
    { re: /\b(action\s*=\s*(?:&quot;|"|')[^"'&]*(?:http:|telegram)[^"'&]*)/gi, cls: 'tok-danger' },
    { re: /\b(type\s*=\s*(?:&quot;|"|')?password)/gi, cls: 'tok-warn' },
    { re: /(0x[0-9a-f]{2}(?:\s*,\s*0x[0-9a-f]{2}){5,})/gi, cls: 'tok-danger' },
    { re: /([A-Za-z0-9+/]{120,}={0,2})/g, cls: 'tok-danger' },
    { re: /&lt;!--[\s\S]*?--&gt;/g, cls: 'tok-comment' }
  ];

  function buildAnnotated(html, findings, maxLines) {
    const lines = String(html).split('\n');
    const limit = Math.min(lines.length, maxLines || 500);
    const flagged = new Set();
    findings.forEach(f => { if (f.line) flagged.add(f.line); });
    let out = '';
    for (let i = 0; i < limit; i++) {
      let escaped = esc(lines[i]);
      TOKEN_RULES.forEach(tr => {
        escaped = escaped.replace(tr.re, match => `<span class="${tr.cls}">${match}</span>`);
      });
      const isFlagged = flagged.has(i + 1);
      out += `<div class="code-line ${isFlagged ? 'flagged' : ''}"><span class="ln">${i + 1}</span><span class="lc">${escaped || ' '}</span></div>`;
    }
    if (lines.length > limit) {
      out += `<div class="code-line"><span class="ln">…</span><span class="lc tok-comment">// ${lines.length - limit} further lines truncated in the viewer (full source was analysed)</span></div>`;
    }
    return out;
  }

  /* ------------------------------------------------------------
     Main exporter
     ------------------------------------------------------------ */
  function analyzeWebpageDOM(htmlString) {
    const html = String(htmlString || '');
    const findings = [];
    const seenIds = new Map();
    const add = (f) => {
      const count = seenIds.get(f.id) || 0;
      if (count >= 2) return;
      seenIds.set(f.id, count + 1);
      findings.push(f);
    };

    if (!html.trim()) {
      return {
        engine: 'dom-inspector-v1', valid: false, score: 0, findings: [], annotatedCodeHtml: '',
        evidence: [{ tone: 'info', text: 'No HTML/JS source supplied.' }],
        stats: { bytes: 0, lines: 0, scripts: 0, forms: 0, frames: 0, externalScripts: 0 },
        highlights: []
      };
    }

    detectForms(html, add);
    detectObfuscation(html, add);
    detectHiddenElements(html, add);
    detectAntiInspection(html, add);
    detectExfiltration(html, add);
    detectSocialTricks(html, add);

    const scripts = (html.match(/<script\b/gi) || []).length;
    const forms = (html.match(/<form\b/gi) || []).length;
    const frames = (html.match(/<(?:iframe|embed|object|frame)\b/gi) || []).length;
    const externalScripts = (html.match(/<script\b[^>]*\bsrc\s*=/gi) || []).length;
    const passwordFields = (html.match(/type\s*=\s*["']?password/gi) || []).length;

    /* unique findings by id, keeping max weight */
    const unique = [];
    const byId = new Map();
    findings.forEach(f => {
      if (!byId.has(f.id)) { byId.set(f.id, f); unique.push(f); }
      else {
        const cur = byId.get(f.id);
        if (f.weight > cur.weight) { byId.set(f.id, f); const i = unique.indexOf(cur); unique[i] = f; }
      }
    });

    const points = unique.reduce((s, f) => s + f.weight, 0);
    let score = points > 0 ? 100 * (1 - Math.exp(-points / 30)) : 0;

    /* Clean-page credit: well-formed HTTPS form with no obfuscation */
    const critical = unique.filter(f => f.severity === 'critical').length;
    const high = unique.filter(f => f.severity === 'high').length;
    if (unique.length === 0) score = 0;
    if (critical === 0 && high === 0 && unique.length <= 1) score = Math.min(score, 18);
    score = Math.max(0, Math.min(100, Math.round(score)));

    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    unique.sort((a, b) => (severityOrder[a.severity] - severityOrder[b.severity]) || (b.weight - a.weight));

    const evidence = unique.map(f => ({ tone: f.severity === 'critical' || f.severity === 'high' ? 'danger' : 'warn', text: `${f.label}: ${f.detail}` }));
    if (!unique.length) evidence.push({ tone: 'safe', text: 'No credential-harvesting, obfuscation, hidden-frame, anti-inspection or exfiltration pattern was found in this source.' });

    return {
      engine: 'dom-inspector-v1',
      valid: true,
      score,
      riskLevel: score >= 65 ? 'critical' : score >= 35 ? 'elevated' : score >= 15 ? 'guarded' : 'low',
      findings: unique,
      annotatedCodeHtml: buildAnnotated(html, unique, 500),
      evidence,
      stats: {
        bytes: html.length,
        lines: html.split('\n').length,
        scripts, forms, frames, externalScripts, passwordFields,
        critical, high,
        medium: unique.filter(f => f.severity === 'medium').length,
        low: unique.filter(f => f.severity === 'low').length,
        uniqueFindings: unique.length
      },
      highlights: unique.map(f => ({ id: f.id, severity: f.severity, label: f.label, line: f.line }))
    };
  }

  window.DOMBrain = { analyze: analyzeWebpageDOM };
  window.analyzeWebpageDOM = analyzeWebpageDOM;
})();
