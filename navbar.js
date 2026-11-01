/* ============================================================
   XEROX — navbar.js
   Shared sticky header, active-page highlighter, mobile drawer,
   shared footer, API-key settings modal & small shared utilities.
   ============================================================ */
(function () {
  'use strict';

  /* ---------------- Shared utilities (window.XRUtil) ---------------- */
  const XRUtil = {
    escapeHtml(str) {
      return String(str == null ? '' : str)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    },
    escapeRegExp(str) {
      return String(str).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    },
    refreshIcons() {
      if (window.lucide && typeof window.lucide.createIcons === 'function') {
        try { window.lucide.createIcons(); } catch (e) { /* icons unavailable offline — graceful */ }
      }
    },
    toast(message, type) {
      type = type || 'info';
      let host = document.getElementById('xr-toast-host');
      if (!host) {
        host = document.createElement('div');
        host.id = 'xr-toast-host';
        host.style.cssText = 'position:fixed;bottom:22px;right:22px;z-index:900;display:flex;flex-direction:column;gap:9px;max-width:340px;';
        document.body.appendChild(host);
      }
      const colors = {
        info: ['rgba(245, 158, 11, .14)', '#fbbf24', 'rgba(245, 158, 11, .35)'],
        safe: ['rgba(16, 185, 129, .14)', '#10b981', 'rgba(16, 185, 129, .35)'],
        warn: ['rgba(234, 179, 8, .14)', '#eab308', 'rgba(234, 179, 8, .35)'],
        danger: ['rgba(239, 68, 68, .14)', '#ef4444', 'rgba(239, 68, 68, .35)']
      };
      const c = colors[type] || colors.info;
      const el = document.createElement('div');
      el.style.cssText = `background:${c[0]};border:1px solid ${c[2]};color:${c[1]};padding:12px 15px;border-radius:12px;font:500 .84rem Inter,sans-serif;backdrop-filter:blur(14px);box-shadow:0 14px 34px rgba(23, 19, 16, .6);opacity:0;transform:translateY(8px);transition:all .3s ease;`;
      el.textContent = message;
      host.appendChild(el);
      requestAnimationFrame(() => { el.style.opacity = '1'; el.style.transform = 'translateY(0)'; });
      setTimeout(() => {
        el.style.opacity = '0'; el.style.transform = 'translateY(8px)';
        setTimeout(() => el.remove(), 320);
      }, 3400);
    },
    getApiKeys() {
      try {
        return {
          gemini: localStorage.getItem('xerox_gemini_key') || '',
          safeBrowsing: localStorage.getItem('xerox_safebrowsing_key') || ''
        };
      } catch (e) { return { gemini: '', safeBrowsing: '' }; }
    },
    setApiKeys(gemini, safeBrowsing) {
      try {
        if (gemini) localStorage.setItem('xerox_gemini_key', gemini); else localStorage.removeItem('xerox_gemini_key');
        if (safeBrowsing) localStorage.setItem('xerox_safebrowsing_key', safeBrowsing); else localStorage.removeItem('xerox_safebrowsing_key');
        return true;
      } catch (e) {
        console.warn('[XEROX] localStorage unavailable — keys held in memory only.');
        window.__xeroxVolatileKeys = { gemini: gemini || '', safeBrowsing: safeBrowsing || '' };
        return false;
      }
    },
    /* Fetch JSON with a hard timeout — used by every live network engine */
    async fetchJSON(url, opts, timeoutMs) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs || 7000);
      try {
        const res = await fetch(url, Object.assign({ signal: controller.signal, headers: { 'Accept': 'application/json' } }, opts || {}));
        if (!res.ok) throw new Error('HTTP ' + res.status);
        return await res.json();
      } finally {
        clearTimeout(timer);
      }
    }
  };
  window.XRUtil = XRUtil;

  /* ---------------- Navigation configuration ---------------- */
  const NAV = [
    { href: 'index.html', label: 'Home', icon: 'layout-dashboard', key: 'index' },
    { href: 'scanner.html', label: 'Live Shield Scanner', icon: 'scan-search', key: 'scanner' },
    { href: 'architecture.html', label: 'Brain & Tech Stack', icon: 'cpu', key: 'architecture' },
    { href: 'training.html', label: 'Training & Calibration', icon: 'sliders-horizontal', key: 'training' }
  ];

  function currentPageKey() {
    const file = (window.location.pathname.split('/').pop() || 'index.html').toLowerCase();
    if (file === '' || file === 'index.html') return 'index';
    if (file.indexOf('scanner') === 0) return 'scanner';
    if (file.indexOf('architecture') === 0) return 'architecture';
    if (file.indexOf('training') === 0) return 'training';
    return 'index';
  }

  const shieldMark = `
    <span class="brand-mark"><i data-lucide="shield-check"></i></span>
    <span class="brand-name">XER<em>OX</em></span>`;

  /* ---------------- Header ---------------- */
  function renderNavbar() {
    const mount = document.getElementById('xr-navbar');
    if (!mount) return;
    const active = currentPageKey();
    const links = NAV.map(item => `
      <li><a href="${item.href}" class="${item.key === active ? 'active' : ''}" ${item.key === active ? 'aria-current="page"' : ''}>
        <i data-lucide="${item.icon}"></i><span>${item.label}</span>
      </a></li>`).join('');

    mount.innerHTML = `
      <nav class="xr-navbar" aria-label="Primary">
        <div class="container">
          <a href="index.html" class="xr-brand" aria-label="XEROX home">${shieldMark}</a>
          <ul class="xr-nav-links">${links}</ul>
          <div class="xr-nav-actions">
            <button class="btn btn-ghost btn-sm" id="xr-open-settings" title="Optional live API keys" aria-label="API key settings">
              <i data-lucide="key-round"></i><span class="hide-sm">API</span>
            </button>
            <a href="scanner.html" class="btn btn-primary btn-sm" id="xr-nav-launch">
              <i data-lucide="shield-alert"></i><span>Launch Shield</span>
            </a>
            <button class="xr-hamburger" id="xr-hamburger" aria-label="Open menu" aria-expanded="false">
              <i data-lucide="menu"></i>
            </button>
          </div>
        </div>
      </nav>
      <div class="xr-drawer-overlay" id="xr-drawer-overlay"></div>
      <aside class="xr-drawer" id="xr-drawer" aria-label="Mobile navigation">
        <div class="xr-drawer-head">
          <a href="index.html" class="xr-brand">${shieldMark}</a>
          <button class="btn btn-ghost btn-sm" id="xr-drawer-close" aria-label="Close menu"><i data-lucide="x"></i></button>
        </div>
        ${NAV.map(i => `<a href="${i.href}" class="${i.key === active ? 'active' : ''}"><i data-lucide="${i.icon}"></i>${i.label}</a>`).join('')}
        <div style="margin-top:auto;padding-top:18px;border-top:1px solid var(--glass-border);">
          <button class="btn btn-ghost btn-block btn-sm" id="xr-open-settings-mobile"><i data-lucide="key-round"></i>Live API Settings</button>
        </div>
      </aside>`;

    /* Drawer behaviour */
    const drawer = document.getElementById('xr-drawer');
    const overlay = document.getElementById('xr-drawer-overlay');
    const burger = document.getElementById('xr-hamburger');
    const open = () => { drawer.classList.add('open'); overlay.classList.add('open'); burger.setAttribute('aria-expanded', 'true'); document.body.style.overflow = 'hidden'; };
    const close = () => { drawer.classList.remove('open'); overlay.classList.remove('open'); burger.setAttribute('aria-expanded', 'false'); document.body.style.overflow = ''; };
    burger.addEventListener('click', open);
    overlay.addEventListener('click', close);
    document.getElementById('xr-drawer-close').addEventListener('click', close);
    drawer.querySelectorAll('a').forEach(a => a.addEventListener('click', close));
    document.addEventListener('keydown', e => { if (e.key === 'Escape') close(); });

    document.getElementById('xr-open-settings').addEventListener('click', () => openSettingsModal());
    document.getElementById('xr-open-settings-mobile').addEventListener('click', () => { close(); openSettingsModal(); });

    /* Pad body for sticky header offset when a page uses #anchor links */
    XRUtil.refreshIcons();
  }

  /* ---------------- Footer ---------------- */
  function renderFooter() {
    const mount = document.getElementById('xr-footer');
    if (!mount) return;
    mount.innerHTML = `
      <footer class="xr-footer">
        <div class="container">
          <div class="xr-footer-grid">
            <div>
              <a href="index.html" class="xr-brand" style="margin-bottom:14px;">${shieldMark}</a>
              <p style="font-size:.86rem;color:#a8a29e;max-width:320px;">
                Omni-channel AI scam verification for the Catalyst Competition. Know instantly what is
                <span class="text-safe">TRUE</span> and what is a <span class="text-danger">SCAM</span> —
                across messages, calls, links, QR codes and webpages.
              </p>
              <div class="chip-row" style="margin-top:16px;">
                <span class="badge badge-amber"><i data-lucide="shield-check"></i>Runs client-side</span>
                <span class="badge badge-orange"><i data-lucide="lock"></i>No data leaves your device</span>
              </div>
            </div>
            <div>
              <h4>Platform</h4>
              <ul>
                <li><a href="scanner.html">Live Shield Scanner</a></li>
                <li><a href="architecture.html">Brain &amp; Tech Stack</a></li>
                <li><a href="training.html">Training &amp; Calibration</a></li>
                <li><a href="index.html#pillars">The Four Pillars</a></li>
              </ul>
            </div>
            <div>
              <h4>Engines</h4>
              <ul>
                <li><a href="scanner.html?mode=text">Message &amp; Email NLP</a></li>
                <li><a href="scanner.html?mode=call">Voice Call Guardian</a></li>
                <li><a href="scanner.html?mode=url">URL Random Forest</a></li>
                <li><a href="scanner.html?mode=qr">QR &amp; Screenshot OCR</a></li>
                <li><a href="scanner.html?mode=code">DOM Script Inspector</a></li>
              </ul>
            </div>
            <div>
              <h4>Competition</h4>
              <ul>
                <li><a href="README.md">Project README</a></li>
                <li><a href="training.html#datasets">Training Datasets</a></li>
                <li><a href="training.html#compare">Comparison Matrix</a></li>
                <li><a href="index.html#quick">Try the 60-second demo</a></li>
              </ul>
            </div>
          </div>
          <div class="xr-footer-bottom">
            <span>© ${new Date().getFullYear()} XEROX — Catalyst Competition entry. Built with vanilla JS, zero backend.</span>
            <span class="mono" style="color:#57534e;">DNS · RDAP · Web Speech · jsQR · Tesseract · Transformers.js</span>
          </div>
        </div>
      </footer>`;
    XRUtil.refreshIcons();
  }

  /* ---------------- Optional API key modal ---------------- */
  function openSettingsModal() {
    let overlay = document.getElementById('xr-settings-modal');
    const keys = XRUtil.getApiKeys();
    if (!overlay) {
      overlay = document.createElement('div');
      overlay.id = 'xr-settings-modal';
      overlay.className = 'xr-modal-overlay';
      overlay.innerHTML = `
        <div class="xr-modal" role="dialog" aria-modal="true" aria-labelledby="xr-settings-title">
          <div class="flex items-center justify-between mb-1">
            <h3 id="xr-settings-title">Live API Enhancement <span class="badge badge-amber">Optional</span></h3>
            <button class="btn btn-ghost btn-sm" id="xr-settings-x" aria-label="Close"><i data-lucide="x"></i></button>
          </div>
          <p class="modal-sub">XEROX works fully offline with its local engines. Add keys to layer a live Gemini deep-check and Google Safe Browsing reputation lookup on top of every scan.</p>

          <div class="field">
            <label><i data-lucide="sparkles"></i>Gemini API Key</label>
            <div class="api-key-field">
              <input type="password" class="input" id="xr-gemini-key" placeholder="AIza..." autocomplete="off" spellcheck="false">
              <button class="key-toggle" data-toggle-key="xr-gemini-key" aria-label="Show or hide key"><i data-lucide="eye"></i></button>
            </div>
            <span class="input-hint">Used for structured JSON verdicts via generativelanguage.googleapis.com</span>
          </div>

          <div class="field">
            <label><i data-lucide="globe-lock"></i>Google Safe Browsing Key</label>
            <div class="api-key-field">
              <input type="password" class="input" id="xr-safebrowsing-key" placeholder="AIza..." autocomplete="off" spellcheck="false">
              <button class="key-toggle" data-toggle-key="xr-safebrowsing-key" aria-label="Show or hide key"><i data-lucide="eye"></i></button>
            </div>
            <span class="input-hint">Queried for every URL and QR-decoded link</span>
          </div>

          <div class="alert-strip info" style="margin-top:6px;">
            <i data-lucide="lock"></i>
            <span>Keys are stored only in this browser's <code>localStorage</code> inside a try/catch guard. Nothing is transmitted anywhere except the respective Google API endpoint.</span>
          </div>

          <div class="xr-modal-actions">
            <button class="btn btn-ghost btn-sm" id="xr-clear-keys"><i data-lucide="trash-2"></i>Clear keys</button>
            <button class="btn btn-primary btn-sm" id="xr-save-keys"><i data-lucide="save"></i>Save keys</button>
          </div>
        </div>`;
      document.body.appendChild(overlay);
      XRUtil.refreshIcons();

      overlay.addEventListener('click', e => { if (e.target === overlay) overlay.classList.remove('open'); });
      document.getElementById('xr-settings-x').addEventListener('click', () => overlay.classList.remove('open'));
      overlay.querySelectorAll('.key-toggle').forEach(btn => {
        btn.addEventListener('click', () => {
          const input = document.getElementById(btn.getAttribute('data-toggle-key'));
          input.type = input.type === 'password' ? 'text' : 'password';
        });
      });
      document.getElementById('xr-save-keys').addEventListener('click', () => {
        const g = document.getElementById('xr-gemini-key').value.trim();
        const s = document.getElementById('xr-safebrowsing-key').value.trim();
        const persisted = XRUtil.setApiKeys(g, s);
        overlay.classList.remove('open');
        XRUtil.toast(persisted ? 'Live API keys saved in this browser.' : 'Keys saved for this tab only (storage blocked).', 'safe');
        document.dispatchEvent(new CustomEvent('xerox:keys-updated', { detail: { gemini: g, safeBrowsing: s } }));
      });
      document.getElementById('xr-clear-keys').addEventListener('click', () => {
        XRUtil.setApiKeys('', '');
        document.getElementById('xr-gemini-key').value = '';
        document.getElementById('xr-safebrowsing-key').value = '';
        XRUtil.toast('Live API keys cleared. Local engines remain active.', 'info');
        document.dispatchEvent(new CustomEvent('xerox:keys-updated', { detail: { gemini: '', safeBrowsing: '' } }));
      });
    }
    document.getElementById('xr-gemini-key').value = keys.gemini;
    document.getElementById('xr-safebrowsing-key').value = keys.safeBrowsing;
    overlay.classList.add('open');
    XRUtil.refreshIcons();
  }

  /* ---------------- Reveal-on-scroll ---------------- */
  function initReveal() {
    const els = document.querySelectorAll('.reveal');
    if (!els.length) return;
    if (!('IntersectionObserver' in window)) { els.forEach(el => el.classList.add('in-view')); return; }
    const io = new IntersectionObserver(entries => {
      entries.forEach(en => { if (en.isIntersecting) { en.target.classList.add('in-view'); io.unobserve(en.target); } });
    }, { threshold: 0.12, rootMargin: '0px 0px -40px 0px' });
    els.forEach(el => io.observe(el));
    /* Fail-safe: if the observer never fires (very tall viewport, print, stitching),
       reveal everything after a short delay so no section can stay blank. */
    setTimeout(() => {
      if (document.querySelectorAll('.reveal:not(.in-view)').length) {
        document.body.classList.add('reveal-fallback');
      }
    }, 2200);
  }

  /* ---------------- Boot ---------------- */
  function boot() {
    renderNavbar();
    renderFooter();
    initReveal();
    XRUtil.refreshIcons();
    /* Lucide script may load after us if the CDN is slow */
    setTimeout(XRUtil.refreshIcons, 400);
    setTimeout(XRUtil.refreshIcons, 1400);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
