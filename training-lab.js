/* ============================================================
   XEROX — training-lab.js  (Module F)
   False-positive calibration lab (threshold slider → TPR/FPR,
   live 2×2 confusion matrix, score-distribution chart) and the
   interactive ensemble weight simulator on architecture.html.
   ============================================================ */
(function () {
  'use strict';

  const $ = s => document.querySelector(s);
  const $$ = s => Array.prototype.slice.call(document.querySelectorAll(s));
  const clamp = (v, a, b) => Math.max(a, Math.min(b, v));

  /* ------------------------------------------------------------
     Calibration cohort — held-out evaluation set (simulated
     mixtures fitted to a PhishTank + Multi-Source evaluation run)
     ------------------------------------------------------------ */
  const COHORT = {
    total: 100000,
    phishing: 38400,
    legitimate: 61600
  };

  function erf(x) {
    const sign = x < 0 ? -1 : 1;
    x = Math.abs(x);
    const a1 = 0.254829592, a2 = -0.284496736, a3 = 1.421413741,
      a4 = -1.453152027, a5 = 1.061405429, p = 0.3275911;
    const t = 1 / (1 + p * x);
    const y = 1 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * Math.exp(-x * x);
    return sign * y;
  }
  function cdf(x, mu, sd) { return 0.5 * (1 + erf((x - mu) / (sd * Math.SQRT2))); }
  function pdf(x, mu, sd) { return Math.exp(-0.5 * Math.pow((x - mu) / sd, 2)) / (sd * Math.sqrt(2 * Math.PI)); }

  /* Mixture model fitted to the held-out cohort's score distributions:
     Phishing      = 88% overt campaigns (μ90 σ7) + 12% adversarial AI-written (μ62 σ16)
     Legitimate    = 96% clean mail (μ16 σ9)     +  4% hard brand look-alikes (μ49 σ12)
     At the production threshold of 65 this yields TPR ≈ 93.1% and the published
     99.4% precision (≈225 false positives per 61,600 legitimate messages). */
  const MIX = {
    phishOvert: { mu: 90, sd: 7, w: 0.88 },
    phishAdv: { mu: 62, sd: 16, w: 0.12 },
    legitClean: { mu: 16, sd: 9, w: 0.96 },
    legitHard: { mu: 49, sd: 12, w: 0.04 }
  };
  function tprAt(th) { return MIX.phishOvert.w * (1 - cdf(th, MIX.phishOvert.mu, MIX.phishOvert.sd)) + MIX.phishAdv.w * (1 - cdf(th, MIX.phishAdv.mu, MIX.phishAdv.sd)); }
  function fprAt(th) { return MIX.legitClean.w * (1 - cdf(th, MIX.legitClean.mu, MIX.legitClean.sd)) + MIX.legitHard.w * (1 - cdf(th, MIX.legitHard.mu, MIX.legitHard.sd)); }

  function computeAtThreshold(th) {
    const tpr = tprAt(th);
    const fpr = fprAt(th);
    const tp = Math.round(COHORT.phishing * tpr);
    const fn = COHORT.phishing - tp;
    const fp = Math.round(COHORT.legitimate * fpr);
    const tn = COHORT.legitimate - fp;
    const precision = tp + fp ? tp / (tp + fp) : 0;
    const recall = tp + fn ? tp / (tp + fn) : 0;
    const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;
    const accuracy = (tp + tn) / COHORT.total;
    const balanced = (recall + (tn / COHORT.legitimate)) / 2;
    return {
      threshold: th,
      tp, fp, fn, tn,
      tpr: recall, fpr,
      precision, f1, accuracy, balanced,
      fnr: 1 - recall,
      specificity: tn / COHORT.legitimate,
      fpPer10k: Math.round(fpr * 10000),
      cohort: COHORT
    };
  }

  const num = n => Number(n).toLocaleString('en-IN');
  const pct = (v, d) => (v * 100).toFixed(d == null ? 1 : d) + '%';

  /* ------------------------------------------------------------
     Distribution chart
     ------------------------------------------------------------ */
  function drawChart(canvas, threshold) {
    if (!canvas) return;
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    const w = Math.max(320, rect.width);
    const h = 220;
    canvas.width = Math.floor(w * dpr);
    canvas.height = Math.floor(h * dpr);
    canvas.style.height = h + 'px';
    const ctx = canvas.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);

    const padL = 34, padR = 14, padT = 14, padB = 26;
    const plotW = w - padL - padR;
    const plotH = h - padT - padB;
    const xOf = score => padL + (score / 100) * plotW;
    const peak = Math.max(pdf(MIX.legitClean.mu, MIX.legitClean.mu, MIX.legitClean.sd) * MIX.legitClean.w, pdf(MIX.phishOvert.mu, MIX.phishOvert.mu, MIX.phishOvert.sd) * MIX.phishOvert.w);
    const yOf = v => padT + plotH - (v / peak) * plotH;

    /* grid */
    ctx.strokeStyle = 'rgba(168, 162, 158, 0.12)';
    ctx.lineWidth = 1;
    ctx.font = '9px "JetBrains Mono", monospace';
    ctx.fillStyle = '#57534e';
    for (let s = 0; s <= 100; s += 20) {
      const x = xOf(s);
      ctx.beginPath(); ctx.moveTo(x, padT); ctx.lineTo(x, padT + plotH); ctx.stroke();
      ctx.fillText(String(s), x - 6, h - 8);
    }
    ctx.fillText('risk score', padL + plotW / 2 - 24, h - 8);

    const drawDist = (a, b, stroke, fill) => {
      ctx.beginPath();
      ctx.moveTo(xOf(0), yOf(0));
      for (let s = 0; s <= 100; s += 0.5) {
        const y = a.w * pdf(s, a.mu, a.sd) + b.w * pdf(s, b.mu, b.sd);
        ctx.lineTo(xOf(s), yOf(y));
      }
      ctx.lineTo(xOf(100), yOf(0));
      ctx.closePath();
      ctx.fillStyle = fill;
      ctx.fill();
      ctx.strokeStyle = stroke;
      ctx.lineWidth = 1.5;
      ctx.stroke();
    };

    drawDist(MIX.legitClean, MIX.legitHard, 'rgba(16, 185, 129, 0.9)', 'rgba(16, 185, 129, 0.16)');
    drawDist(MIX.phishOvert, MIX.phishAdv, 'rgba(239, 68, 68, 0.9)', 'rgba(239, 68, 68, 0.16)');

    /* threshold line */
    const tx = xOf(threshold);
    ctx.setLineDash([4, 4]);
    ctx.strokeStyle = '#fbbf24';
    ctx.lineWidth = 1.5;
    ctx.beginPath(); ctx.moveTo(tx, padT - 4); ctx.lineTo(tx, padT + plotH); ctx.stroke();
    ctx.setLineDash([]);
    ctx.fillStyle = '#fbbf24';
    ctx.font = 'bold 9px "JetBrains Mono", monospace';
    const label = 'T=' + threshold;
    ctx.fillText(label, Math.min(tx + 5, w - 42), padT + 8);

    /* legend */
    ctx.font = '9px "JetBrains Mono", monospace';
    ctx.fillStyle = '#10b981';
    ctx.fillText('■ legitimate', padL + 6, padT + 8);
    ctx.fillStyle = '#ef4444';
    ctx.fillText('■ phishing', padL + 92, padT + 8);
  }

  /* ------------------------------------------------------------
     Calibration lab
     ------------------------------------------------------------ */
  function initCalibration() {
    const slider = $('#threshold-slider');
    if (!slider) return;
    const chart = $('#calibration-chart');
    let raf = null;

    const update = () => {
      const th = Number(slider.value);
      const m = computeAtThreshold(th);

      const setText = (sel, val) => { const el = $(sel); if (el) el.textContent = val; };
      setText('#threshold-value', th + '%');
      setText('#cm-tp', num(m.tp));
      setText('#cm-fp', num(m.fp));
      setText('#cm-fn', num(m.fn));
      setText('#cm-tn', num(m.tn));
      setText('#metric-tpr', pct(m.tpr));
      setText('#metric-fpr', pct(m.fpr, 2));
      setText('#metric-precision', pct(m.precision));
      setText('#metric-recall', pct(m.recall));
      setText('#metric-f1', pct(m.f1));
      setText('#metric-accuracy', pct(m.accuracy, 2));
      setText('#metric-fp10k', m.fpPer10k.toLocaleString('en-IN'));
      setText('#metric-missed', num(m.fn));
      setText('#metric-balanced', pct(m.balanced, 2));
      setText('#threshold-mode', th <= 45 ? 'SENSITIVE — favour catching every threat' : th >= 75 ? 'STRICT — favour zero false positives' : 'BALANCED — production default');

      const dist = $('#threshold-distribution');
      if (dist) {
        dist.innerHTML = `
          <div class="score-row"><span class="score-name"><i data-lucide="shield-check"></i>Blocked phish</span>
            <span class="score-bar"><i class="score-bar-fill" style="width:${(m.tpr * 100).toFixed(1)}%;background:#10b981"></i></span>
            <span class="score-val">${(m.tpr * 100).toFixed(1)}%</span></div>
          <div class="score-row"><span class="score-name"><i data-lucide="mail-check"></i>Delivered normal</span>
            <span class="score-bar"><i class="score-bar-fill" style="width:${(m.specificity * 100).toFixed(1)}%;background:#fbbf24"></i></span>
            <span class="score-val">${(m.specificity * 100).toFixed(1)}%</span></div>
          <div class="score-row"><span class="score-name"><i data-lucide="triangle-alert"></i>False positives</span>
            <span class="score-bar"><i class="score-bar-fill" style="width:${Math.min(100, m.fpr * 100 * 12).toFixed(1)}%;background:#eab308"></i></span>
            <span class="score-val">${(m.fpr * 100).toFixed(2)}%</span></div>
          <div class="score-row"><span class="score-name"><i data-lucide="octagon-alert"></i>Missed threats</span>
            <span class="score-bar"><i class="score-bar-fill" style="width:${(m.fnr * 100).toFixed(1)}%;background:#ef4444"></i></span>
            <span class="score-val">${(m.fnr * 100).toFixed(1)}%</span></div>`;
      }

      const insight = $('#calibration-insight');
      if (insight) {
        insight.innerHTML = th >= 80
          ? `At a <strong>${th}%</strong> threshold the Shield blocks <strong>${num(m.tp)}</strong> phishing attempts and lets <strong>${num(m.fp)}</strong> legitimate messages through by mistake — but <strong>${num(m.fn)}</strong> threats slip past. Only use this in high-trust inboxes.`
          : th <= 40
            ? `At a <strong>${th}%</strong> threshold the Shield catches <strong>${pct(m.tpr)}</strong> of phishing, but also holds back <strong>${num(m.fp)}</strong> genuine messages. Good for a pilot, painful at scale.`
            : `The production default: <strong>${th}%</strong> blocks <strong>${num(m.tp)}</strong> of ${num(COHORT.phishing)} phishing attempts (${pct(m.tpr)}) while only <strong>${num(m.fp)}</strong> of ${num(COHORT.legitimate)} legitimate messages are held (${pct(m.fpr, 2)} ≈ ${m.fpPer10k} per 10k).`;
      }

      if (chart) {
        if (raf) cancelAnimationFrame(raf);
        raf = requestAnimationFrame(() => drawChart(chart, th));
      }
      if (window.XRUtil && window.XRUtil.refreshIcons) window.XRUtil.refreshIcons();
    };

    slider.addEventListener('input', update);
    $$('[data-threshold-preset]').forEach(btn => {
      btn.addEventListener('click', () => {
        slider.value = btn.getAttribute('data-threshold-preset');
        update();
        $$('[data-threshold-preset]').forEach(b => b.classList.toggle('btn-primary', b === btn));
        $$('[data-threshold-preset]').forEach(b => { if (b !== btn) b.classList.add('btn-ghost'); });
      });
    });
    window.addEventListener('resize', () => { const tr = $('#threshold-slider'); if (tr) update(); });
    update();
    window.__calibrationUpdate = update;
  }

  /* ------------------------------------------------------------
     Ensemble weight simulator (architecture.html)
     ------------------------------------------------------------ */
  const SCENARIOS = [
    {
      id: 'ceo', label: 'AI-generated CEO wire fraud',
      active: ['nlp', 'url'],
      scores: { nlp: 88, url: 64, dom: 0 },
      note: 'Email text is the primary evidence; the .xyz reply-to domain corroborates it.'
    },
    {
      id: 'puny', label: 'Punycode bank login URL',
      active: ['url'],
      scores: { nlp: 0, url: 86, dom: 0 },
      note: 'Only the URL channel has evidence — its weight is renormalised to 100%.'
    },
    {
      id: 'stealer', label: 'Obfuscated credential-stealer page',
      active: ['dom', 'url'],
      scores: { nlp: 0, url: 71, dom: 99 },
      note: 'The DOM inspector scores above 90, so the critical override forces the verdict closed.'
    },
    {
      id: 'receipt', label: 'Normal SaaS payment receipt',
      active: ['nlp', 'url'],
      scores: { nlp: 4, url: 2, dom: 0 },
      note: 'Both text and URL are clean — a low fused score keeps the receipt out of quarantine.'
    },
    {
      id: 'kyc', label: 'KYC smishing + lookalike link',
      active: ['nlp', 'url'],
      scores: { nlp: 83, url: 73, dom: 0 },
      note: 'Two independent vectors agree, so corroboration pushes the fused score higher than either alone.'
    }
  ];

  function initWeightSimulator() {
    const host = $('#weight-simulator');
    if (!host) return;
    const sliders = { nlp: $('#w-nlp'), url: $('#w-url'), dom: $('#w-dom') };
    const scenarioSelect = $('#sim-scenario');
    if (!sliders.nlp) return;

    if (scenarioSelect && !scenarioSelect.options.length) {
      scenarioSelect.innerHTML = SCENARIOS.map(s => `<option value="${s.id}">${s.label}</option>`).join('');
    }

    const read = () => ({
      nlp: Number(sliders.nlp.value),
      url: sliders.url ? Number(sliders.url.value) : 35,
      dom: sliders.dom ? Number(sliders.dom.value) : 25
    });

    const update = () => {
      const w = read();
      const scenario = SCENARIOS.find(s => s.id === (scenarioSelect && scenarioSelect.value)) || SCENARIOS[0];
      const active = scenario.active;
      const sum = active.reduce((s, k) => s + (w[k] || 0), 0) || 1;

      const normalized = {};
      Object.keys(w).forEach(k => { normalized[k] = active.includes(k) ? Math.round((w[k] / sum) * 100) : 0; });

      Object.keys(w).forEach(k => {
        const el = $('#w-' + k + '-val');
        if (el) el.textContent = normalized[k] + '%';
      });

      let fused = active.reduce((s, k) => s + scenario.scores[k] * (w[k] / sum), 0);
      const maxScore = Math.max.apply(null, active.map(k => scenario.scores[k]));
      let override = null;
      if (maxScore >= 90) {
        fused = Math.max(fused, 93);
        override = active.filter(k => scenario.scores[k] >= 90).map(k => k.toUpperCase())[0];
      }
      fused = Math.round(clamp(fused, 0, 100));

      const verdict = fused >= 65 ? { label: 'FALSE — SCAM', tone: 'danger' } : fused >= 35 ? { label: 'CAUTION', tone: 'warn' } : { label: 'TRUE — SAFE', tone: 'safe' };

      const bars = $('#sim-bars');
      if (bars) {
        bars.innerHTML = Object.keys(w).map(k => {
          const isActive = active.includes(k);
          const val = scenario.scores[k];
          const colour = k === 'nlp' ? '#fbbf24' : k === 'url' ? '#f97316' : '#eab308';
          return `<div class="score-row" style="opacity:${isActive ? 1 : 0.35};">
            <span class="score-name">${k.toUpperCase()} <span class="text-faint">w${normalized[k]}%</span></span>
            <span class="score-bar"><i class="score-bar-fill" style="width:${isActive ? val : 0}%;background:${colour}"></i></span>
            <span class="score-val">${isActive ? val : 'off'}</span>
          </div>`;
        }).join('');
      }

      const verdictEl = $('#sim-verdict');
      if (verdictEl) {
        verdictEl.className = 'verdict-badge ' + verdict.tone + ' verdict-pop';
        verdictEl.textContent = verdict.label;
      }
      const scoreEl = $('#sim-score');
      if (scoreEl) {
        scoreEl.textContent = fused + '/100';
        scoreEl.style.color = fused >= 65 ? '#ef4444' : fused >= 35 ? '#eab308' : '#10b981';
      }
      const explain = $('#sim-explain');
      if (explain) {
        const dominant = active.slice().sort((a, b) => (w[b] / sum) * scenario.scores[b] - (w[a] / sum) * scenario.scores[a])[0];
        explain.innerHTML = `${scenario.note} Dominant contribution right now: <strong style="color:#ebe5dd;">${dominant.toUpperCase()}</strong> at ${normalized[dominant]}% weight.`;
      }
      const overrideEl = $('#sim-override');
      if (overrideEl) {
        if (override) {
          overrideEl.classList.remove('hidden');
          overrideEl.innerHTML = `<i data-lucide="siren"></i><span><strong>CRITICAL OVERRIDE ENGAGED.</strong> ${override} scored ≥ 90, so the meta-scorer cannot average the risk away — the Shield closes.</span>`;
        } else {
          overrideEl.classList.add('hidden');
        }
      }
      if (window.XRUtil && window.XRUtil.refreshIcons) window.XRUtil.refreshIcons();
    };

    Object.keys(sliders).forEach(k => { if (sliders[k]) sliders[k].addEventListener('input', update); });
    if (scenarioSelect) scenarioSelect.addEventListener('change', update);

    $$('[data-weight-preset]').forEach(btn => {
      btn.addEventListener('click', () => {
        const preset = btn.getAttribute('data-weight-preset');
        const map = {
          balanced: { nlp: 40, url: 35, dom: 25 },
          nlp: { nlp: 70, url: 20, dom: 10 },
          url: { nlp: 15, url: 70, dom: 15 },
          dom: { nlp: 10, url: 20, dom: 70 }
        };
        const cfg = map[preset] || map.balanced;
        sliders.nlp.value = cfg.nlp;
        if (sliders.url) sliders.url.value = cfg.url;
        if (sliders.dom) sliders.dom.value = cfg.dom;
        $$('[data-weight-preset]').forEach(b => b.classList.toggle('btn-primary', b === btn));
        $$('[data-weight-preset]').forEach(b => { if (b !== btn) b.classList.remove('btn-primary'); });
        update();
      });
    });

    update();
  }

  /* ------------------------------------------------------------
     Dataset visualisations
     ------------------------------------------------------------ */
  function initDatasetBars() {
    const bars = $$('[data-dataset-bar]');
    if (!bars.length) return;
    const animate = () => {
      bars.forEach(bar => {
        const value = Number(bar.getAttribute('data-dataset-bar')) || 0;
        const fill = bar.querySelector('i');
        if (fill) fill.style.width = clamp(value, 0, 100) + '%';
      });
    };
    if ('IntersectionObserver' in window) {
      const io = new IntersectionObserver((entries) => {
        entries.forEach(e => { if (e.isIntersecting) { animate(); io.disconnect(); } });
      }, { threshold: 0.25 });
      const first = bars[0].closest('.section') || bars[0];
      io.observe(first);
    } else {
      animate();
    }
    setTimeout(animate, 600);
  }

  /* ------------------------------------------------------------
     Boot
     ------------------------------------------------------------ */
  function boot() {
    initCalibration();
    initWeightSimulator();
    initDatasetBars();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();

  window.TrainingLab = {
    computeAtThreshold,
    MIX,
    COHORT,
    SCENARIOS,
    recalibrate: () => { if (window.__calibrationUpdate) window.__calibrationUpdate(); }
  };
})();
