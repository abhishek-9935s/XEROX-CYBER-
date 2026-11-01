/* ============================================================
   XEROX — background-cycler.js
   A living, colourful background with two rhythms:

   1. CONTINUOUS DRIFT  — the aurora hues creep forward every tick,
                          so the page is always subtly changing colour.
   2. PALETTE CHANGE    — every 45 minutes (configurable) the site
                          advances to the next of 100 generated
                          palettes and glides to it over ~1.4s.

   State (index / since / interval / paused) is persisted in
   localStorage, so the 45-minute cadence survives reloads and even
   closed tabs — reopening after two hours advances two palettes.
   ============================================================ */
(function () {
  'use strict';

  const TOTAL_PALETTES = 100;
  const DEFAULT_INTERVAL = 45 * 60 * 1000;   /* 45 minutes */
  const DRIFT_PER_SECOND = 0.35;             /* degrees of hue per second */
  const STORE = {
    index: 'xr_bg_index',
    since: 'xr_bg_since',
    interval: 'xr_bg_interval',
    paused: 'xr_bg_paused'
  };

  /* ------------------------------------------------------------
     Palette geometry — golden-angle walk guarantees 100 distinct,
     evenly-spread palettes instead of 100 near-identical blues.
     ------------------------------------------------------------ */
  /* Five colour-harmony schemes rotate alongside the golden-angle hue walk.
     Without this, fixed offsets keep h1 and h2 analogous, so every palette
     reads as the same green/magenta wash. Rotating the scheme makes
     consecutive palettes genuinely different rooms. */
  const SCHEMES = [
    { name: 'analogous',          off: [0, 32, 64, 328] },
    { name: 'complementary',      off: [0, 180, 152, 208] },
    { name: 'split-complementary', off: [0, 150, 210, 28] },
    { name: 'triadic',            off: [0, 120, 240, 62] },
    { name: 'tetradic',           off: [0, 90, 180, 270] }
  ];

  function huesFor(i) {
    const base = (i * 137.508 + 18) % 360;
    const scheme = SCHEMES[i % SCHEMES.length];
    const j = (i % 7) * 3;             /* small jitter keeps all 100 unique */
    return {
      h1: base,
      h2: ((base + scheme.off[1] + j) % 360 + 360) % 360,
      h3: ((base + scheme.off[2] + j * 2) % 360 + 360) % 360,
      h4: ((base + scheme.off[3] + j * 3) % 360 + 360) % 360,
      scheme: scheme.name
    };
  }

  const FAMILIES = [
    [345, 'Crimson'], [12, 'Ember'], [28, 'Tangerine'], [42, 'Amber'],
    [56, 'Gold'], [78, 'Lime'], [112, 'Emerald'], [150, 'Jade'],
    [176, 'Teal'], [194, 'Cyan'], [212, 'Azure'], [238, 'Indigo'],
    [262, 'Violet'], [288, 'Orchid'], [312, 'Magenta'], [332, 'Rose']
  ];
  const VARIANTS = ['Drift', 'Bloom', 'Haze', 'Pulse', 'Veil', 'Tide', 'Aurora', 'Surge'];

  function nameFor(i) {
    const h = huesFor(i).h1;
    let family = FAMILIES[0][1];
    let best = 999;
    FAMILIES.forEach(f => {
      const d = Math.min(Math.abs(h - f[0]), 360 - Math.abs(h - f[0]));
      if (d < best) { best = d; family = f[1]; }
    });
    return family + ' ' + VARIANTS[i % VARIANTS.length];
  }

  /* ------------------------------------------------------------
     Persisted state
     ------------------------------------------------------------ */
  const store = {
    read(key, fallback) {
      try {
        const v = localStorage.getItem(key);
        return v === null ? fallback : v;
      } catch (e) { return fallback; }
    },
    write(key, value) {
      try { localStorage.setItem(key, String(value)); } catch (e) { /* private mode */ }
    }
  };

  const now = () => Date.now();

  const state = {
    index: ((parseInt(store.read(STORE.index, '0'), 10) || 0) % TOTAL_PALETTES + TOTAL_PALETTES) % TOTAL_PALETTES,
    since: parseInt(store.read(STORE.since, '0'), 10) || 0,
    interval: (() => {
      const v = parseInt(store.read(STORE.interval, String(DEFAULT_INTERVAL)), 10);
      return Number.isFinite(v) && v >= 0 ? v : DEFAULT_INTERVAL;
    })(),
    paused: store.read(STORE.paused, '0') === '1',
    drift: 0,
    current: { h1: 0, h2: 0, h3: 0, h4: 0 },
    raf: null,
    tickTimer: null
  };

  const reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  /* On first run, or after an invalid timestamp, anchor to now */
  if (!state.since || state.since > now() || state.since < now() - 1000 * 60 * 60 * 24 * 365) {
    state.since = now();
    store.write(STORE.since, state.since);
  }

  /* Catch up on palettes that elapsed while the tab was closed */
  (function catchUp() {
    if (state.paused || state.interval <= 0) return;
    const steps = Math.floor((now() - state.since) / state.interval);
    if (steps > 0) {
      state.index = (state.index + steps) % TOTAL_PALETTES;
      state.since = state.since + steps * state.interval;
      store.write(STORE.index, state.index);
      store.write(STORE.since, state.since);
    }
  })();

  /* ------------------------------------------------------------
     Painting
     ------------------------------------------------------------ */
  function paint(hues) {
    const root = document.documentElement;
    const d = state.drift;
    const h = {
      h1: (hues.h1 + d) % 360,
      h2: (hues.h2 + d) % 360,
      h3: (hues.h3 + d) % 360,
      h4: (hues.h4 + d) % 360
    };
    root.style.setProperty('--xr-h1', h.h1.toFixed(2));
    root.style.setProperty('--xr-h2', h.h2.toFixed(2));
    root.style.setProperty('--xr-h3', h.h3.toFixed(2));
    root.style.setProperty('--xr-h4', h.h4.toFixed(2));

    /* Ambient tokens used by body::before / body::after in main.css */
    root.style.setProperty('--bg-glow-1', `hsla(${h.h1.toFixed(1)}, 92%, 56%, 0.17)`);
    root.style.setProperty('--bg-glow-2', `hsla(${h.h2.toFixed(1)}, 95%, 58%, 0.10)`);
    root.style.setProperty('--bg-glow-3', `hsla(${h.h3.toFixed(1)}, 88%, 56%, 0.11)`);
    root.style.setProperty('--bg-grid', `hsla(${h.h1.toFixed(1)}, 92%, 56%, 0.05)`);
  }

  /* Smooth glide between palettes (rAF lerp, ~1.4s) */
  function glideTo(target, duration) {
    if (state.raf) cancelAnimationFrame(state.raf);
    const from = { h1: state.current.h1, h2: state.current.h2, h3: state.current.h3, h4: state.current.h4 };
    const start = performance.now();
    const dur = reduceMotion ? 0 : (duration || 1400);

    const step = (t) => {
      const p = dur === 0 ? 1 : Math.min(1, (t - start) / dur);
      const e = p < 0.5 ? 2 * p * p : 1 - Math.pow(-2 * p + 2, 2) / 2; /* easeInOutQuad */
      const mix = (a, b) => {
        let d = ((b - a + 540) % 360) - 180; /* shortest way around the wheel */
        return (a + d * e + 360) % 360;
      };
      state.current = {
        h1: mix(from.h1, target.h1),
        h2: mix(from.h2, target.h2),
        h3: mix(from.h3, target.h3),
        h4: mix(from.h4, target.h4)
      };
      paint(state.current);
      if (p < 1) state.raf = requestAnimationFrame(step);
      else { state.raf = null; state.current = Object.assign({}, target); }
    };
    state.raf = requestAnimationFrame(step);
  }

  /* Snap without animation (initial mount / reduced motion) */
  function snapTo(target) {
    state.current = Object.assign({}, target);
    paint(state.current);
  }

  /* ------------------------------------------------------------
     Advancement
     ------------------------------------------------------------ */
  function applyIndex(nextIndex, opts) {
    state.index = ((nextIndex % TOTAL_PALETTES) + TOTAL_PALETTES) % TOTAL_PALETTES;
    state.drift = 0;
    store.write(STORE.index, state.index);
    const target = huesFor(state.index);
    if (opts && opts.instant) snapTo(target); else glideTo(target);
    updatePanel();
  }

  function advance(dir) {
    applyIndex(state.index + (dir || 1));
    state.since = now();
    store.write(STORE.since, state.since);
  }

  const tick = () => {
    if (!state.paused) {
      if (state.interval > 0 && now() - state.since >= state.interval) {
        /* Scheduled palette change — the 45-minute rhythm */
        state.index = (state.index + 1) % TOTAL_PALETTES;
        state.since = now();
        state.drift = 0;
        store.write(STORE.index, state.index);
        store.write(STORE.since, state.since);
        if (state.raf) cancelAnimationFrame(state.raf);
        glideTo(huesFor(state.index), 2200);
        updatePanel();
      } else if (!reduceMotion) {
        /* Continuous drift — the "always changing" rhythm */
        state.drift = (state.drift + DRIFT_PER_SECOND * 0.25) % 360;
        if (!state.raf) paint(state.current);
      }
    }
  };

  /* ------------------------------------------------------------
     DOM
     ------------------------------------------------------------ */
  function buildAurora() {
    if (document.getElementById('xr-aurora')) return;
    const layer = document.createElement('div');
    layer.id = 'xr-aurora';
    layer.setAttribute('aria-hidden', 'true');
    layer.innerHTML = '<span class="xr-orb o1"></span><span class="xr-orb o2"></span><span class="xr-orb o3"></span><span class="xr-orb o4"></span>';
    document.body.insertBefore(layer, document.body.firstChild);
  }

  let panelEls = null;

  function buildPanel() {
    if (document.getElementById('xr-bg-panel')) {
      panelEls = {
        root: document.getElementById('xr-bg-panel'),
        name: document.querySelector('#xr-bg-panel .xr-bg-name'),
        play: document.querySelector('#xr-bg-panel [data-bg="play"]'),
        select: document.getElementById('xr-bg-interval')
      };
      return;
    }
    const panel = document.createElement('div');
    panel.id = 'xr-bg-panel';
    panel.setAttribute('role', 'group');
    panel.setAttribute('aria-label', 'Background colour palette');
    panel.innerHTML = `
      <span class="xr-bg-dot" aria-hidden="true"></span>
      <span class="xr-bg-name">—</span>
      <span class="xr-bg-controls">
        <button type="button" data-bg="prev" aria-label="Previous palette" title="Previous palette">‹</button>
        <button type="button" data-bg="play" aria-label="Pause colour cycling" title="Pause / resume">❚❚</button>
        <button type="button" data-bg="next" aria-label="Next palette" title="Next palette">›</button>
        <select id="xr-bg-interval" aria-label="Palette change interval" title="Palette change interval">
          <option value="60000">1 min</option>
          <option value="900000">15 min</option>
          <option value="2700000">45 min</option>
          <option value="10800000">3 hrs</option>
          <option value="0">manual</option>
        </select>
      </span>`;
    document.body.appendChild(panel);

    panelEls = {
      root: panel,
      name: panel.querySelector('.xr-bg-name'),
      play: panel.querySelector('[data-bg="play"]'),
      select: panel.querySelector('#xr-bg-interval')
    };

    panel.addEventListener('click', (e) => {
      const btn = e.target.closest('[data-bg]');
      if (!btn) return;
      const action = btn.getAttribute('data-bg');
      if (action === 'next') advance(1);
      else if (action === 'prev') advance(-1);
      else if (action === 'play') togglePaused();
    });

    panelEls.select.addEventListener('change', (e) => {
      setInterval_(parseInt(e.target.value, 10));
    });
  }

  function updatePanel() {
    if (!panelEls) return;
    const label = String(state.index + 1).padStart(3, '0') + ' / ' + TOTAL_PALETTES + ' · ' + nameFor(state.index);
    panelEls.name.textContent = label;
    panelEls.root.setAttribute('title', 'Background palette ' + (state.index + 1) + ' of ' + TOTAL_PALETTES + ' — ' + nameFor(state.index));
    if (panelEls.play) {
      panelEls.play.textContent = state.paused ? '▶' : '❚❚';
      panelEls.play.setAttribute('aria-label', state.paused ? 'Resume colour cycling' : 'Pause colour cycling');
      panelEls.play.title = state.paused ? 'Resume cycling' : 'Pause cycling';
    }
    if (panelEls.select) {
      const val = String(state.interval);
      const has = Array.prototype.some.call(panelEls.select.options, o => o.value === val);
      if (has) panelEls.select.value = val;
    }
  }

  function togglePaused() {
    state.paused = !state.paused;
    store.write(STORE.paused, state.paused ? '1' : '0');
    updatePanel();
  }

  function setInterval_(ms) {
    state.interval = Number.isFinite(ms) && ms >= 0 ? ms : DEFAULT_INTERVAL;
    store.write(STORE.interval, state.interval);
    /* Restart the clock so a fresh interval begins now */
    state.since = now();
    store.write(STORE.since, state.since);
    updatePanel();
    if (window.XRUtil && window.XRUtil.toast) {
      window.XRUtil.toast(state.interval === 0 ? 'Palette cycling set to manual.' : 'Palette changes every ' + Math.round(state.interval / 60000) + ' min.', 'info');
    }
  }

  /* ------------------------------------------------------------
     Boot
     ------------------------------------------------------------ */
  function boot() {
    buildAurora();
    buildPanel();
    snapTo(huesFor(state.index));   /* instant first paint — no flash */
    updatePanel();
    state.tickTimer = window.setInterval(tick, 250);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();

  /* Recalculate if the user changes OS motion preference mid-session */
  if (window.matchMedia) {
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
    if (mq.addEventListener) mq.addEventListener('change', () => { if (mq.matches && state.raf) { cancelAnimationFrame(state.raf); state.raf = null; } });
  }

  /* ------------------------------------------------------------
     Public API (also used by the test harness)
     ------------------------------------------------------------ */
  window.XEROXBackground = {
    TOTAL_PALETTES,
    hueFor: huesFor,
    nameFor,
    next: () => advance(1),
    prev: () => advance(-1),
    goTo: (i) => applyIndex(i),
    pause: togglePaused,
    setInterval: setInterval_,
    state: () => ({
      index: state.index,
      name: nameFor(state.index),
      scheme: huesFor(state.index).scheme,
      interval: state.interval,
      paused: state.paused,
      since: state.since,
      drifted: Math.round(state.drift * 10) / 10,
      hues: Object.assign({}, state.current)
    })
  };
})();
