/* ============================================================
   XEROX — ensemble-controller.js  (Master module)
   Fuses every channel into one calibrated TRUE / CAUTION / FALSE
   verdict, then binds the full scanner + quick-verify UI.
   ============================================================ */
(function () {
  'use strict';

  const esc = s => String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  const $ = sel => document.querySelector(sel);
  const $$ = sel => Array.prototype.slice.call(document.querySelectorAll(sel));
  const clamp = (v, a, b) => Math.max(a, Math.min(b, v));

  const BASE_WEIGHTS = { nlp: 0.40, url: 0.35, dom: 0.25, call: 0.40, qr: 0.35 };
  const CHANNEL_LABEL = { text: 'Message / Email', call: 'Voice call', url: 'URL / Link', qr: 'QR / Screenshot', code: 'Webpage code', all: 'Unified multi-channel' };

  const state = {
    mode: 'text',
    lastResult: null,
    log: [],
    scanCount: 0,
    qr: { payload: '', previewSrc: '', file: null, ocrText: '', camera: null },
    call: { controller: null, finalText: '' },
    busy: false
  };

  /* ============================================================
     PART 1 — THE ENSEMBLE BRAIN
     ============================================================ */
  function normalizeInput(input) {
    if (typeof input === 'string') {
      const v = input.trim();
      if (/^https?:\/\//i.test(v) || /^www\./i.test(v) || /^[a-z0-9-]+(\.[a-z0-9-]+)+(\/|$)/i.test(v)) return { mode: 'url', url: v };
      if (/<\w+[\s>]|<\/\w+>/.test(v)) return { mode: 'code', html: v };
      return { mode: 'text', body: v };
    }
    return Object.assign({ mode: 'text' }, input || {});
  }

  function firstUrlsFrom(text, limit) {
    if (!text || !window.NLPEngine) return [];
    const found = window.NLPEngine.extractUrls(text).map(u => u.url);
    const unique = [];
    found.forEach(u => { if (!unique.includes(u)) unique.push(u); });
    return unique.slice(0, limit || 2);
  }

  async function safe(fn, fallback) {
    try { return await fn(); } catch (e) {
      console.warn('[XEROX] engine error:', e);
      return Object.assign({ error: e.message || String(e) }, fallback || {});
    }
  }

  async function scan(input, opts) {
    opts = opts || {};
    const payload = normalizeInput(input);
    const meta = (payload.meta || {});
    const started = performance.now();
    const components = [];
    const xai = { nlp: null, url: null, dom: null, call: null, qr: null };
    const notes = [];
    const mode = payload.mode || 'text';

    /* ---------- Message / Email channel ---------- */
    const messageText = [payload.subject || '', payload.body || ''].join('\n').trim();
    const includeText = mode === 'text' || mode === 'all' || (mode === 'qr' && (payload.ocrText || payload.qrContext));
    if (includeText && window.NLPEngine) {
      const sourceBody = payload.ocrText || payload.body || payload.qrContext || '';
      const nlp = await safe(() => Promise.resolve(window.NLPEngine.analyze(payload.subject || '', payload.sender || '', sourceBody)), null);
      if (nlp) {
        /* If the user loaded the real DistilBERT ONNX model, blend its probability in. */
        const neuralState = window.NLPEngine.getNeuralState ? window.NLPEngine.getNeuralState() : { ready: false };
        if (neuralState.ready && String(sourceBody).trim().length > 20) {
          const neural = await safe(() => window.NLPEngine.classifyWithNeural([payload.subject || '', sourceBody].join('\n')), null);
          if (neural && typeof neural.phishingProb === 'number') {
            nlp.localScore = nlp.score;
            nlp.neuralScore = Math.round(neural.phishingProb * 100);
            nlp.score = Math.round(nlp.score * 0.65 + neural.phishingProb * 100 * 0.35);
            nlp.neural = { status: 'ready', model: neural.model, phishingProb: neural.phishingProb, labels: neural.labels };
            nlp.reasons.push({
              tone: nlp.neuralScore >= 65 ? 'danger' : nlp.neuralScore >= 35 ? 'warn' : 'safe',
              text: `DistilBERT neural layer: ${nlp.neuralScore}% phishing probability on the raw text (blended 35% into the NLP score).`
            });
            notes.push('DistilBERT ONNX inference included.');
          }
        }
        xai.nlp = nlp;
        components.push({ key: 'nlp', label: 'Semantic NLP', icon: 'brain-circuit', score: nlp.score, confidence: nlp.confidence, weight: BASE_WEIGHTS.nlp });
        notes.push(`${nlp.triggers.length} linguistic signature(s) from ${nlp.stats.rulesEvaluated} evaluated rules.`);
      }
    }

    /* ---------- URL channel ---------- */
    let urlCandidates = [];
    if (mode === 'url' && payload.url) urlCandidates = [payload.url];
    else if (mode === 'all' && payload.url) urlCandidates = [payload.url];
    else urlCandidates = firstUrlsFrom(messageText, 2);
    if (mode === 'qr' && payload.qrPayload && /^https?:\/\//i.test(payload.qrPayload)) urlCandidates = [payload.qrPayload];
    if (mode === 'code' && payload.html) {
      const htmlUrls = firstUrlsFrom(payload.html.replace(/<[^>]+>/g, ' '), 1);
      urlCandidates = urlCandidates.concat(htmlUrls).slice(0, 2);
    }

    if (urlCandidates.length && window.URLBrain) {
      const results = [];
      for (const candidate of urlCandidates.slice(0, 2)) {
        const r = await safe(() => window.URLBrain.analyzeUrlFull(candidate, {
          onStage: (stage) => { if (opts.onStage) opts.onStage(stage); }
        }), null);
        if (r && r.valid) results.push(r);
      }
      if (results.length) {
        const worst = results.slice().sort((a, b) => b.score - a.score)[0];
        xai.url = worst;
        xai.urls = results;
        components.push({ key: 'url', label: 'URL Random Forest + live DNS/RDAP', icon: 'globe-lock', score: worst.score, confidence: worst.live && worst.live.status === 'complete' ? 0.93 : 0.78, weight: BASE_WEIGHTS.url });
        notes.push(`16 structural features computed on ${worst.anatomy.rootDomain}; live telemetry ${worst.live && worst.live.status === 'complete' ? 'attached' : 'unavailable'}.`);
      }
    }

    /* ---------- Voice-call channel ---------- */
    if ((mode === 'call' || mode === 'all') && payload.transcript && window.VoiceGuard) {
      const call = await safe(() => Promise.resolve(window.VoiceGuard.analyzeTranscript(payload.transcript, payload.caller || '')), null);
      if (call) {
        xai.call = call;
        components.push({ key: 'call', label: 'Vishing signature analysis', icon: 'phone-call', score: call.score, confidence: call.confidence, weight: BASE_WEIGHTS.call });
        notes.push(`${call.callHits.length} call-specific signature(s); ${call.criticalSignals.length} critical.`);
      }
    }

    /* ---------- Webpage code channel ---------- */
    if ((mode === 'code' || mode === 'all') && payload.html && window.DOMBrain) {
      const dom = await safe(() => Promise.resolve(window.DOMBrain.analyze(payload.html)), null);
      if (dom) {
        xai.dom = dom;
        components.push({ key: 'dom', label: 'DOM & script inspector', icon: 'code-2', score: dom.score, confidence: dom.stats.uniqueFindings > 4 ? 0.95 : 0.82, weight: BASE_WEIGHTS.dom });
        notes.push(`${dom.stats.uniqueFindings} code finding(s); ${dom.stats.critical} critical.`);
      }
    }

    /* ---------- QR / OCR channel ---------- */
    if (mode === 'qr' || (mode === 'all' && (payload.qrPayload || payload.ocrText))) {
      if (payload.qrPayload && window.QRBrain) {
        const qr = await safe(() => window.QRBrain.analyzePayload(payload.qrPayload, { context: payload.qrContext, onStage: opts.onStage }), null);
        if (qr) {
          xai.qr = qr;
          if (qr.type === 'upi') {
            components.push({ key: 'qr', label: 'UPI QR analysis', icon: 'qr-code', score: qr.score, confidence: qr.confidence, weight: BASE_WEIGHTS.qr });
            notes.push('UPI payload decoded and parsed.');
          } else if (qr.type === 'url' && qr.anatomy) {
            xai.url = qr;
            components.push({ key: 'url', label: 'QR → URL verification', icon: 'globe-lock', score: qr.score, confidence: 0.9, weight: BASE_WEIGHTS.url });
            notes.push('QR resolves to a web link; URL engine applied.');
          } else if (qr.type === 'text') {
            xai.nlp = qr.nlp || xai.nlp;
            components.push({ key: 'nlp', label: 'QR text → NLP', icon: 'brain-circuit', score: qr.score, confidence: 0.8, weight: BASE_WEIGHTS.nlp });
          }
          if (payload.qrContext && window.NLPEngine) {
            const ctxNlp = window.NLPEngine.analyze('', '', payload.qrContext);
            xai.qrContextNlp = ctxNlp;
            if (ctxNlp.score >= 35) {
              components.push({ key: 'nlp', label: 'Caption NLP', icon: 'message-square', score: ctxNlp.score, confidence: ctxNlp.confidence, weight: 0.15 });
            }
          }
        }
      }
    }

    /* ---------- Fusion ---------- */
    if (!components.length) {
      return {
        ok: false,
        error: 'Nothing to analyse — provide a message, URL, transcript, QR payload or HTML source.',
        latencyMs: Math.round(performance.now() - started)
      };
    }

    const weightSum = components.reduce((s, c) => s + c.weight, 0) || 1;
    let fused = components.reduce((s, c) => s + (c.score * c.weight), 0) / weightSum;

    /* Corroboration bonus — independent vectors agreeing raises confidence */
    const activeScores = components.map(c => c.score);
    const strongCount = components.filter(c => c.score >= 55).length;
    if (strongCount >= 2) fused += 5;
    if (components.length >= 3 && activeScores.every(s => s >= 45)) fused += 4;

    /* Critical override: any single vector ≥ 90 forces the shield closed */
    const maxComponent = components.slice().sort((a, b) => b.score - a.score)[0];
    let override = null;
    if (maxComponent.score >= 90) {
      fused = Math.max(fused, 93);
      override = { channel: maxComponent.label, score: maxComponent.score, reason: `${maxComponent.label} independently scored ${maxComponent.score}/100 — above the 90-point critical threshold, which overrides weighted averaging.` };
    }

    fused = clamp(Math.round(fused), 0, 100);

    const verdict = fused >= 65
      ? { key: 'false', tone: 'danger', label: 'FALSE', badgeText: 'FALSE — CONFIRMED SCAM', headline: 'FALSE — CONFIRMED SCAM / PHISHING', description: 'Multiple independent engines agree this is fraudulent. The Shield blocks it.', action: fused >= 80 ? 'BLOCKED BY SHIELD' : 'QUARANTINE & WARN USER', icon: 'shield-x' }
      : fused >= 35
        ? { key: 'caution', tone: 'warn', label: 'CAUTION', badgeText: 'CAUTION — SUSPICIOUS', headline: 'CAUTION — UNVERIFIED / SUSPICIOUS', description: 'Some risk signals are present but the evidence is not conclusive. Verify through an official channel before acting.', action: 'HOLD & REQUEST VERIFICATION', icon: 'shield-alert' }
        : { key: 'true', tone: 'safe', label: 'TRUE', badgeText: 'TRUE — VERIFIED SAFE', headline: 'TRUE — VERIFIED LEGITIMATE & SAFE', description: 'No meaningful scam signature crossed threshold. Delivery is permitted.', action: 'ALLOW — MONITORED', icon: 'shield-check' };

    const confidencePct = Math.round(clamp(
      components.reduce((s, c) => s + (c.confidence || 0.8) * c.weight, 0) / weightSum * 100 + (override ? 3 : 0),
      55, 99
    ));

    /* Evidence synthesis */
    const evidence = [];
    const seen = new Set();
    const pushEvidence = (tone, text) => {
      const key = String(text).slice(0, 80);
      if (seen.has(key)) return;
      seen.add(key);
      evidence.push({ tone, text });
    };

    if (xai.call) xai.call.evidence.forEach(e => pushEvidence(e.tone, e.text));
    if (xai.dom) xai.dom.evidence.forEach(e => pushEvidence(e.tone, e.text));
    if (xai.url) xai.url.evidence.forEach(e => pushEvidence(e.tone, e.text));
    if (xai.qr && xai.qr.evidence) xai.qr.evidence.forEach(e => pushEvidence(e.tone, e.text));
    if (xai.nlp) xai.nlp.reasons.forEach(e => pushEvidence(e.tone, e.text));
    if (override) evidence.unshift({ tone: 'danger', text: 'CRITICAL OVERRIDE — ' + override.reason });
    if (!evidence.length) evidence.push({ tone: 'safe', text: 'All active engines returned low-risk readings.' });

    let recommendation;
    if (verdict.key === 'false') {
      const map = {
        call: 'Hang up now. Do not share any OTP, PIN or screen access. Report to cybercrime.gov.in or dial 1930.',
        url: 'Do not open this link. Block the domain at DNS/proxy level and warn the recipient.',
        qr: 'Do not scan or approve this payment. UPI QR codes only debit money — never credit it.',
        code: 'Block the page. The source contains credential-harvesting or obfuscated script patterns.',
        text: 'Quarantine the message, block the sender and alert the recipient. Do not click any embedded link.',
        all: 'Block the message and link, quarantine the payload and warn the user across all channels.'
      };
      recommendation = map[mode] || map.text;
    } else if (verdict.key === 'caution') {
      recommendation = 'Do not act yet. Verify the sender/caller through an independent official channel (number on your card, official app, known colleague).';
    } else {
      recommendation = 'No action required. Continue monitoring — XEROX re-scores every new message, link and call.';
    }

    const result = {
      ok: true,
      id: 'scan-' + Date.now() + '-' + Math.floor(Math.random() * 1000),
      mode,
      channelLabel: CHANNEL_LABEL[mode] || 'Scan',
      input: payload,
      score: fused,
      verdict,
      confidence: confidencePct,
      components: components.map(c => ({ key: c.key, label: c.label, icon: c.icon, score: Math.round(c.score), weight: Math.round((c.weight / weightSum) * 100), confidence: Math.round((c.confidence || 0.8) * 100) })),
      weights: components.map(c => ({ key: c.key, raw: c.weight, normalized: Math.round((c.weight / weightSum) * 100) })),
      evidence: evidence.slice(0, 9),
      override,
      recommendation,
      notes,
      latencyMs: Math.round(performance.now() - started),
      timestamp: new Date(),
      xai
    };
    return result;
  }

  /* ============================================================
     PART 2 — RENDERING HELPERS
     ============================================================ */
  const toneColor = tone => tone === 'danger' ? '#ef4444' : tone === 'warn' ? '#eab308' : tone === 'safe' ? '#10b981' : '#fbbf24';
  const scoreColor = s => s >= 65 ? '#ef4444' : s >= 35 ? '#eab308' : '#10b981';

  function setGauge(score) {
    const ring = $('#risk-ring');
    const num = $('#risk-score');
    const caption = $('#risk-caption');
    if (!ring) return;
    const color = scoreColor(score);
    const deg = clamp(score, 0, 100) * 3.6;
    ring.style.background = `conic-gradient(from 210deg, ${color} 0deg, ${color} ${Math.max(deg, 2)}deg, rgba(168, 162, 158, 0.12) ${Math.max(deg, 2)}deg 360deg)`;
    ring.classList.toggle('gauge-danger', score >= 80);
    if (num) {
      num.style.color = color;
      const target = Math.round(score);
      let cur = 0;
      const step = Math.max(1, Math.round(target / 34));
      const timer = setInterval(() => {
        cur += step;
        if (cur >= target) { cur = target; clearInterval(timer); }
        num.innerHTML = cur + '<span class="pct">/100</span>';
      }, 16);
    }
    if (caption) caption.textContent = score >= 65 ? 'HIGH RISK' : score >= 35 ? 'ELEVATED RISK' : 'LOW RISK';
  }

  function renderVerdict(result) {
    const banner = $('#verdict-banner');
    if (!banner) return;
    banner.className = 'verdict-banner ' + result.verdict.tone;
    const badge = $('#verdict-badge');
    if (badge) {
      badge.className = 'verdict-badge ' + result.verdict.tone + ' verdict-pop';
      badge.innerHTML = `<i data-lucide="${result.verdict.icon}"></i><span>${result.verdict.badgeText || result.verdict.headline}</span>`;
    }
    const title = $('#verdict-title');
    if (title) title.textContent = result.verdict.description;
    const desc = $('#verdict-desc');
    if (desc) desc.textContent = result.recommendation;
    const lat = $('#stat-latency');
    if (lat) lat.textContent = result.latencyMs + ' ms';
    const conf = $('#stat-confidence');
    if (conf) conf.textContent = result.confidence + '%';
    const action = $('#stat-action');
    if (action) { action.textContent = result.verdict.action; action.style.color = toneColor(result.verdict.tone); }
    const scoreMeta = $('#stat-score');
    if (scoreMeta) { scoreMeta.textContent = result.score + ' / 100'; scoreMeta.style.color = scoreColor(result.score); }
    const modeBadge = $('#verdict-mode');
    if (modeBadge) modeBadge.innerHTML = `<i data-lucide="radio"></i>${esc(result.channelLabel)} · ${result.confidence}% confidence`;
    if (window.XRUtil) window.XRUtil.refreshIcons();
  }

  function renderComponentBars(result) {
    const host = $('#component-bars');
    if (!host) return;
    host.innerHTML = result.components.map(c => {
      const col = scoreColor(c.score);
      return `<div class="score-row" title="${esc(c.label)} — weight ${c.weight}%">
        <span class="score-name"><i data-lucide="${c.icon}"></i>${esc(c.label.split(' ')[0])}</span>
        <span class="score-bar"><i class="score-bar-fill" style="width:${c.score}%;background:${col}"></i></span>
        <span class="score-val">${c.score}</span>
      </div>`;
    }).join('') + `<div class="text-xs mono text-faint" style="margin-top:6px;">Normalised ensemble weights: ${result.components.map(c => c.key + ' ' + c.weight + '%').join(' · ')}</div>`;
    if (window.XRUtil) window.XRUtil.refreshIcons();
  }

  /* ---------- NLP tab ---------- */
  function renderNlpTab(result) {
    const host = $('#xai-nlp');
    if (!host) return;
    const nlp = result.xai.nlp;
    const call = result.xai.call;
    if (!nlp && !call) {
      host.innerHTML = `<div class="log-empty"><i data-lucide="brain-circuit"></i>No linguistic channel was active for this scan. Scan a message, call transcript or screenshot to populate the NLP view.</div>`;
      if (window.XRUtil) window.XRUtil.refreshIcons();
      return;
    }

    let html = '';

    if (call) {
      html += `<div class="alert-strip ${call.criticalSignals.length ? 'danger' : 'info'}" style="margin-bottom:16px;">
        <i data-lucide="phone-call"></i>
        <div><strong>${call.criticalSignals.length ? 'CRITICAL VISHING ALERT' : 'Call analysis complete'}</strong><br>${esc(call.advice)}</div>
      </div>`;
      if (call.callHits.length) {
        html += `<div class="card-title" style="margin-top:4px;"><i data-lucide="radio"></i>Call-specific signatures</div>
        <div class="chip-row" style="margin-bottom:18px;">${call.callHits.map(h => `<span class="badge ${h.severity === 'critical' ? 'badge-danger' : h.severity === 'high' ? 'badge-warn' : 'badge-neutral'}"><i data-lucide="${h.severity === 'critical' ? 'siren' : 'alert-triangle'}"></i>${esc(h.label)}</span>`).join('')}</div>`;
      }
    }

    if (nlp) {
      html += `<div class="message-surface">${nlp.highlightedHtml || '<span class="text-faint">No text body supplied.</span>'}</div>`;
      html += `<p class="input-hint" style="margin-top:8px;">Highlighted spans are the exact phrases that fired a rule. Hover any highlight for the explanation.</p>`;

      if (nlp.categories && nlp.categories.length) {
        html += `<div class="card-title" style="margin-top:22px;"><i data-lucide="radar"></i>Intent categories</div>`;
        html += nlp.categories.map(c => `<div class="score-row">
          <span class="score-name"><i data-lucide="${c.icon}"></i>${esc(c.label)}</span>
          <span class="score-bar"><i class="score-bar-fill" style="width:${c.strength}%;background:${toneColor(c.strength >= 65 ? 'danger' : c.strength >= 35 ? 'warn' : 'safe')}"></i></span>
          <span class="score-val">${c.count}</span>
        </div>`).join('');
      }

      if (nlp.triggers.length) {
        html += `<div class="card-title" style="margin-top:20px;"><i data-lucide="list-warning"></i>Fired rules (${nlp.triggers.length})</div>
        <ul class="xai-list">${nlp.triggers.slice(0, 9).map(t => `<li class="${t.severity}">
          <span class="xi"><i data-lucide="${t.severity === 'danger' ? 'octagon-alert' : 'alert-triangle'}"></i></span>
          <span><strong>${esc(t.label)}</strong> <span class="badge badge-neutral" style="margin-left:4px;">${esc(t.categoryLabel)}</span><br>${esc(t.detail)}</span>
        </li>`).join('')}</ul>`;
      } else {
        html += `<div class="alert-strip safe" style="margin-top:18px;"><i data-lucide="shield-check"></i><span>No manipulation rule fired. The message does not ask for credentials, money, secrecy or remote access.</span></div>`;
      }

      if (nlp.legitSignals.length) {
        html += `<div class="card-title" style="margin-top:20px;"><i data-lucide="badge-check"></i>Legitimate-context signals</div>
        <div class="chip-row">${nlp.legitSignals.map(l => `<span class="badge badge-safe"><i data-lucide="check"></i>${esc(l.label)}</span>`).join('')}</div>`;
      }

      if (nlp.sender && nlp.sender.domain) {
        html += `<div class="card-title" style="margin-top:20px;"><i data-lucide="at-sign"></i>Sender forensics</div>
        <div class="data-table-wrap"><table class="data-table"><tbody>
          <tr><td class="text-muted">Display name</td><td class="cell-mono">${esc(nlp.sender.display || '—')}</td></tr>
          <tr><td class="text-muted">Envelope address</td><td class="cell-mono">${esc(nlp.sender.address || '—')}</td></tr>
          <tr><td class="text-muted">Sending domain</td><td class="cell-mono">${esc(nlp.sender.domain)}</td></tr>
          <tr><td class="text-muted">Sender anomalies</td><td>${nlp.sender.signals.length ? nlp.sender.signals.map(s => `<span class="badge badge-warn">${esc(s.label)}</span>`).join(' ') : '<span class="badge badge-safe">none detected</span>'}</td></tr>
        </tbody></table></div>`;
      }

      if (nlp.extractedUrls.length || nlp.extractedPhones.length) {
        html += `<div class="card-title" style="margin-top:20px;"><i data-lucide="link"></i>Extracted indicators</div><div class="chip-row">
          ${nlp.extractedUrls.map(u => `<span class="badge badge-amber mono">${esc(u)}</span>`).join('')}
          ${nlp.extractedPhones.map(p => `<span class="badge badge-neutral mono">${esc(p)}</span>`).join('')}
        </div>`;
      }

      html += `<div class="telemetry-grid" style="margin-top:20px;">
        <div class="telemetry-item"><div class="t-label"><i data-lucide="percent"></i>NLP risk${nlp.neuralScore != null ? ' (blended)' : ''}</div><div class="t-value" style="color:${scoreColor(nlp.score)}">${nlp.score}/100</div><div class="t-sub">${nlp.neuralScore != null ? 'rules ' + nlp.localScore + ' · DistilBERT ' + nlp.neuralScore + ' (35%)' : 'rule confidence ' + (nlp.confidence * 100).toFixed(0) + '%'}</div></div>
        <div class="telemetry-item"><div class="t-label"><i data-lucide="scale"></i>Raw / legit points</div><div class="t-value">${nlp.stats.rawPoints}${nlp.legitPoints > 0 ? ` <span class="text-faint" style="font-size:.8rem;">− ${Math.round(nlp.legitPoints)}</span>` : ''}</div><div class="t-sub">${nlp.stats.matchedRules} rules fired${nlp.legitPoints > 0 ? ' · legit offset' : ''}</div></div>
      </div>`;
    }

    host.innerHTML = html;
    if (window.XRUtil) window.XRUtil.refreshIcons();
  }

  /* ---------- URL tab ---------- */
  function renderUrlTab(result) {
    const host = $('#xai-url');
    if (!host) return;
    const r = result.xai.url;
    if (!r) {
      host.innerHTML = `<div class="log-empty"><i data-lucide="globe-lock"></i>No URL channel was active. Enter or paste a link, or include one in a message or QR code.</div>`;
      if (window.XRUtil) window.XRUtil.refreshIcons();
      return;
    }
    const a = r.anatomy || {};
    const live = r.live || {};
    const dns = live.dns;
    const rdap = live.rdap;

    let html = `<div class="flex items-center justify-between wrap gap-2" style="margin-bottom:10px;">
      <span class="chip-row">
        <span class="badge ${r.score >= 65 ? 'badge-danger' : r.score >= 35 ? 'badge-warn' : 'badge-safe'}">Structural risk ${r.score}/100</span>
        ${r.trustedHost ? '<span class="badge badge-safe"><i data-lucide="badge-check"></i>Trusted root</span>' : ''}
        ${a.isIP ? '<span class="badge badge-danger">Raw IP host</span>' : ''}
      </span>
      <span class="text-xs mono text-faint">${esc(a.hostname || '')}</span>
    </div>`;

    html += `<div class="url-anatomy">
      <div class="url-part p-proto risk-low"><span class="up-label">Protocol</span><span class="up-value">${esc(a.protocol || '—')}</span></div>
      <div class="url-part p-sub ${a.subdomain ? 'risk-high' : 'risk-low'}"><span class="up-label">Subdomain</span><span class="up-value">${esc(a.subdomain || '(none)')}</span></div>
      <div class="url-part p-root ${r.brand ? 'risk-high' : 'risk-low'}"><span class="up-label">Root domain</span><span class="up-value">${esc(a.rootDomain || '—')}</span></div>
      <div class="url-part p-tld"><span class="up-label">TLD</span><span class="up-value">.${esc(a.tld || '—')}</span></div>
      <div class="url-part p-path" style="flex:1;"><span class="up-label">Path</span><span class="up-value">${esc((a.path || '/') + (a.query || ''))}</span></div>
    </div>`;

    if (a.decodedHost && a.decodedHost !== a.hostname) {
      html += `<div class="alert-strip warn" style="margin-bottom:14px;"><i data-lucide="languages"></i><div>Punycode decoded: <code class="mono">${esc(a.hostname)}</code> renders as <code class="mono">${esc(a.decodedHost)}</code>${r.brand && r.brand.homoglyph ? ' — a homoglyph of the real brand.' : '.'}</div></div>`;
    }

    /* Live telemetry */
    html += `<div class="card-title" style="margin-top:16px;"><i data-lucide="activity"></i>Live network telemetry</div>`;
    if (dns && dns.status !== 'unreachable') {
      html += `<div class="dns-grid">
        <div class="dns-chip ${dns.aRecords && dns.aRecords.length ? '' : 'dead'}"><div class="dc-type">A record</div><div class="dc-val">${dns.aRecords && dns.aRecords.length ? esc(dns.aRecords.slice(0, 2).join(', ')) : (dns.status === 'nxdomain' ? 'NXDOMAIN' : 'none')}</div></div>
        <div class="dns-chip ${dns.hasMX ? '' : 'dead'}"><div class="dc-type">MX record</div><div class="dc-val">${dns.hasMX ? esc(dns.mxRecords.slice(0, 2).map(x => x.exchange).join(', ')) : 'none'}</div></div>
        <div class="dns-chip ${dns.hasSPF ? '' : 'dead'}"><div class="dc-type">SPF (TXT)</div><div class="dc-val">${dns.hasSPF ? esc(dns.spf.slice(0, 60)) : 'not published'}</div></div>
        <div class="dns-chip ${dns.hasDMARC ? '' : 'dead'}"><div class="dc-type">DMARC</div><div class="dc-val">${dns.hasDMARC ? esc(dns.dmarc.slice(0, 60)) : 'not published'}</div></div>
      </div>
      <div class="telemetry-grid" style="margin-top:10px;">
        <div class="telemetry-item"><div class="t-label"><i data-lucide="calendar-clock"></i>Domain age</div><div class="t-value">${rdap && typeof rdap.ageDays === 'number' ? rdap.ageDays.toLocaleString() + ' days' : (rdap && rdap.status === 'unavailable' ? 'unavailable' : '—')}</div><div class="t-sub">${rdap && rdap.registered ? 'registered ' + new Date(rdap.registered).toISOString().slice(0, 10) : (rdap && rdap.error ? esc(String(rdap.error).slice(0, 44)) : 'RDAP')}</div></div>
        <div class="telemetry-item"><div class="t-label"><i data-lucide="server"></i>DNS latency</div><div class="t-value">${dns.latencyMs != null ? dns.latencyMs + ' ms' : '—'}</div><div class="t-sub">Google DNS-over-HTTPS</div></div>
      </div>`;
    } else if (dns && dns.status === 'unreachable') {
      html += `<div class="alert-strip warn"><i data-lucide="wifi-off"></i><span>Live DNS unreachable from this browser (offline or blocked). The 16 structural features below were still computed locally.</span></div>`;
    } else {
      html += `<div class="alert-strip info"><i data-lucide="info"></i><span>Live lookup skipped for this host.</span></div>`;
    }

    if (live.flags && live.flags.length) {
      html += `<div class="card-title" style="margin-top:20px;"><i data-lucide="scan-line"></i>Live flags</div><ul class="xai-list">
        ${live.flags.map(f => `<li class="${f.tone === 'danger' ? 'danger' : f.tone === 'warn' ? 'warn' : f.tone === 'safe' ? 'safe' : 'info'}">
          <span class="xi"><i data-lucide="${f.tone === 'danger' ? 'octagon-alert' : f.tone === 'warn' ? 'alert-triangle' : f.tone === 'safe' ? 'check' : 'info'}"></i></span>
          <span><strong>${esc(f.label)}</strong><br>${esc(f.detail)}</span></li>`).join('')}
      </ul>`;
    }

    if (r.safeBrowsing && r.safeBrowsing.status !== 'not-configured' && r.safeBrowsing.status !== 'not-checked') {
      html += `<div class="alert-strip ${r.safeBrowsing.status === 'threat' ? 'danger' : r.safeBrowsing.status === 'clean' ? 'safe' : 'warn'}" style="margin-top:16px;">
        <i data-lucide="shield-alert"></i><span>Google Safe Browsing: <strong>${esc(r.safeBrowsing.status)}</strong>${r.safeBrowsing.message ? ' — ' + esc(r.safeBrowsing.message) : ''}</span></div>`;
    }

    html += `<div class="card-title" style="margin-top:22px;"><i data-lucide="table-2"></i>16 Random-Forest features</div>
    <div class="data-table-wrap"><table class="data-table">
      <thead><tr><th>Feature</th><th>Value</th><th>Threshold</th><th>Risk</th><th class="num">Pts</th></tr></thead>
      <tbody>${r.features.map(f => `<tr title="${esc(f.explanation)}">
        <td class="cell-mono">${esc(f.key)}</td>
        <td class="cell-mono" style="color:${f.status === 'bad' ? '#fca5a5' : f.status === 'warn' ? '#fde047' : '#d6d0c8'}">${esc(String(f.display))}</td>
        <td class="text-muted" style="font-size:.72rem;">${esc(f.threshold)}</td>
        <td><div class="feat-bar"><i style="width:${Math.min(100, (f.riskContribution / 18) * 100)}%;background:${f.riskContribution >= 8 ? '#ef4444' : f.riskContribution > 0 ? '#eab308' : '#10b981'}"></i></div></td>
        <td class="num" style="color:${f.riskContribution ? '#fca5a5' : '#57534e'}">${f.riskContribution ? '+' + f.riskContribution : '0'}</td>
      </tr>`).join('')}</tbody>
    </table></div>`;

    if (r.brand) {
      html += `<div class="alert-strip danger" style="margin-top:16px;"><i data-lucide="copy-x"></i><span><strong>${esc(r.brand.brand.toUpperCase())} impersonation</strong> — ${esc(r.brand.detail)}</span></div>`;
    }

    host.innerHTML = html;
    if (window.XRUtil) window.XRUtil.refreshIcons();
  }

  /* ---------- DOM tab ---------- */
  function renderDomTab(result) {
    const host = $('#xai-dom');
    if (!host) return;
    const d = result.xai.dom;
    if (!d) {
      host.innerHTML = `<div class="log-empty"><i data-lucide="code-2"></i>No webpage source was analysed. Paste HTML/JS in the Code tab to inspect it.</div>`;
      if (window.XRUtil) window.XRUtil.refreshIcons();
      return;
    }
    let html = `<div class="flex items-center justify-between wrap gap-2" style="margin-bottom:14px;">
      <span class="chip-row">
        <span class="badge ${d.score >= 65 ? 'badge-danger' : d.score >= 35 ? 'badge-warn' : 'badge-safe'}">Code risk ${d.score}/100</span>
        <span class="badge badge-neutral">${d.stats.lines} lines</span>
        <span class="badge badge-neutral">${d.stats.scripts} script blocks</span>
        <span class="badge badge-neutral">${d.stats.frames} frames</span>
      </span>
      <span class="text-xs mono text-faint">${d.stats.bytes.toLocaleString()} bytes</span>
    </div>`;

    if (d.findings.length) {
      html += `<ul class="xai-list" style="margin-bottom:18px;">${d.findings.slice(0, 10).map(f => `<li class="${f.severity === 'critical' || f.severity === 'high' ? 'danger' : 'warn'}">
        <span class="xi"><i data-lucide="${f.severity === 'critical' ? 'octagon-alert' : f.severity === 'high' ? 'alert-triangle' : 'info'}"></i></span>
        <span><strong>${esc(f.label)}</strong> <span class="badge badge-neutral" style="margin-left:4px;">line ${f.line || '?'}</span><br>${esc(f.detail)}
        ${f.snippet ? `<br><code class="mono text-xs" style="color:#78716c;">${esc(f.snippet)}</code>` : ''}</span>
      </li>`).join('')}</ul>`;
    } else {
      html += `<div class="alert-strip safe" style="margin-bottom:18px;"><i data-lucide="shield-check"></i><span>No credential-harvesting, obfuscation, hidden-frame or anti-inspection pattern found.</span></div>`;
    }

    html += `<div class="code-inspector" id="code-inspector-box">
      <div class="code-inspector-bar"><span class="dot r"></span><span class="dot y"></span><span class="dot g"></span><span class="file-name">inspected-source.html</span><span class="lang-tag">DOM · JS</span></div>
      <div class="code-body">${d.annotatedCodeHtml}</div>
    </div>`;

    host.innerHTML = html;
    if (window.XRUtil) window.XRUtil.refreshIcons();
  }

  function renderAll(result) {
    state.lastResult = result;
    setGauge(result.score);
    renderVerdict(result);
    renderComponentBars(result);
    renderNlpTab(result);
    renderUrlTab(result);
    renderDomTab(result);
    renderQrSummary(result);
  }

  function renderQrSummary(result) {
    const host = $('#qr-analysis');
    if (!host) return;
    const qr = result.xai.qr;
    if (!qr) { host.innerHTML = ''; return; }
    let html = `<div class="alert-strip ${qr.score >= 65 ? 'danger' : qr.score >= 35 ? 'warn' : 'safe'}" style="margin-bottom:12px;">
      <i data-lucide="qr-code"></i><div><strong>QR payload decoded · ${esc(qr.type.toUpperCase())}</strong><br><span class="mono text-xs">${esc((qr.qrPayload || qr.payload || '').slice(0, 220))}</span></div>
    </div>`;
    if (qr.type === 'upi' && qr.upi) {
      html += `<div class="telemetry-grid">
        <div class="telemetry-item"><div class="t-label"><i data-lucide="user-round"></i>Payee name</div><div class="t-value" style="font-size:.95rem;">${esc(qr.upi.payeeName || '—')}</div><div class="t-sub">${esc(qr.upi.vpa || 'no VPA')}</div></div>
        <div class="telemetry-item"><div class="t-label"><i data-lucide="indian-rupee"></i>Pre-filled amount</div><div class="t-value">${qr.upi.amount ? '₹' + qr.upi.amount.toLocaleString('en-IN') : 'none'}</div><div class="t-sub">${esc(qr.upi.note || 'no note')}</div></div>
      </div>`;
    }
    host.innerHTML = html;
    if (window.XRUtil) window.XRUtil.refreshIcons();
  }

  /* ---------- Session log ---------- */
  function addLogEntry(result, inputSummary) {
    state.log.unshift({
      id: result.id,
      time: result.timestamp,
      channel: result.channelLabel,
      summary: inputSummary,
      score: result.score,
      verdict: result.verdict,
      falsePositive: false
    });
    state.scanCount++;
    renderLog();
  }

  function renderLog() {
    const body = $('#log-body');
    const count = $('#log-count');
    if (count) count.textContent = state.log.length;
    if (!body) return;
    if (!state.log.length) {
      body.innerHTML = `<tr><td colspan="6"><div class="log-empty"><i data-lucide="inbox"></i>No scans this session. Every scan is retained in memory with a false-positive calibration toggle.</div></td></tr>`;
    } else {
      body.innerHTML = state.log.map(entry => `<tr data-log-id="${entry.id}">
        <td class="cell-mono text-faint">${entry.time.toTimeString().slice(0, 8)}</td>
        <td><span class="badge badge-neutral">${esc(entry.channel)}</span></td>
        <td class="cell-mono" style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${esc(entry.summary)}">${esc(entry.summary)}</td>
        <td class="num" style="color:${scoreColor(entry.score)};font-weight:600;">${entry.score}</td>
        <td><span class="verdict-badge ${entry.verdict.tone}" style="padding:3px 10px;font-size:.66rem;">${entry.verdict.label}</span></td>
        <td>
          <label class="flex items-center gap-1" style="cursor:pointer;font-size:.72rem;color:#a8a29e;">
            <span class="switch"><input type="checkbox" data-fp-toggle="${entry.id}" ${entry.falsePositive ? 'checked' : ''}><span class="track"></span></span>
            <span>Mark FP</span>
          </label>
        </td>
      </tr>`).join('');
    }
    if (window.XRUtil) window.XRUtil.refreshIcons();
  }

  function bindLog() {
    const body = $('#log-body');
    if (!body) return;
    body.addEventListener('change', (e) => {
      const toggle = e.target.closest('[data-fp-toggle]');
      if (!toggle) return;
      const entry = state.log.find(l => l.id === toggle.getAttribute('data-fp-toggle'));
      if (!entry) return;
      entry.falsePositive = toggle.checked;
      if (window.XRUtil) window.XRUtil.toast(toggle.checked ? 'Marked as false positive — logged for threshold recalibration.' : 'False-positive mark removed.', toggle.checked ? 'warn' : 'info');
    });
    const clear = $('#log-clear');
    if (clear) clear.addEventListener('click', () => { state.log = []; renderLog(); if (window.XRUtil) window.XRUtil.toast('Session quarantine log cleared.', 'info'); });
  }

  /* ============================================================
     PART 3 — SCANNER PAGE WIRING
     ============================================================ */
  function inputSummaryFor(mode) {
    if (mode === 'url') return ($('#in-url') && $('#in-url').value.trim()) || 'URL scan';
    if (mode === 'code') return 'HTML source (' + (($('#in-html') && $('#in-html').value.length) || 0) + ' chars)';
    if (mode === 'call') { const t = ($('#in-transcript') && $('#in-transcript').value.trim()) || ''; return t ? t.slice(0, 80) + (t.length > 80 ? '…' : '') : 'Call transcript'; }
    if (mode === 'qr') return state.qr.payload ? 'QR: ' + state.qr.payload.slice(0, 60) : (state.qr.ocrText ? 'Screenshot OCR' : 'QR / image scan');
    const s = ($('#in-subject') && $('#in-subject').value.trim()) || '';
    const b = ($('#in-body') && $('#in-body').value.trim()) || '';
    return s || b.slice(0, 80) || 'Message scan';
  }

  async function gatherPayload(mode) {
    const bodyVal = ($('#in-body') && $('#in-body').value) || '';
    const subjectVal = ($('#in-subject') && $('#in-subject').value) || '';
    const senderVal = ($('#in-sender') && $('#in-sender').value) || '';
    const urlVal = ($('#in-url') && $('#in-url').value.trim()) || '';
    const htmlVal = ($('#in-html') && $('#in-html').value) || '';
    const transcriptVal = ($('#in-transcript') && $('#in-transcript').value.trim()) || state.call.finalText || '';
    const ocrVal = ($('#in-ocr-text') && $('#in-ocr-text').value.trim()) || state.qr.ocrText || '';

    const base = { mode, sender: senderVal, subject: subjectVal, body: bodyVal };

    if (mode === 'url') return Object.assign(base, { url: urlVal });
    if (mode === 'code') return Object.assign(base, { html: htmlVal });
    if (mode === 'call') return Object.assign(base, { transcript: transcriptVal, caller: ($('#in-caller') && $('#in-caller').value) || '' });
    if (mode === 'qr') {
      let payload = state.qr.payload;
      if (!payload && state.qr.previewSrc) {
        try {
          const decoded = await window.QRBrain.decodeImageSource(state.qr.previewSrc);
          payload = decoded.payload || '';
          state.qr.payload = payload;
        } catch (e) { /* library may be offline */ }
      }
      if (!payload && ocrVal) return Object.assign(base, { ocrText: ocrVal, body: ocrVal, qrContext: ($('#in-qr-context') && $('#in-qr-context').value) || '' });
      return Object.assign(base, { qrPayload: payload, ocrText: ocrVal, qrContext: ($('#in-qr-context') && $('#in-qr-context').value) || '', body: bodyVal || ocrVal });
    }
    if (mode === 'all') {
      return Object.assign(base, {
        url: urlVal,
        html: htmlVal,
        transcript: transcriptVal,
        caller: ($('#in-caller') && $('#in-caller').value) || '',
        qrPayload: state.qr.payload,
        qrContext: ($('#in-qr-context') && $('#in-qr-context').value) || '',
        ocrText: ocrVal
      });
    }
    return base;
  }

  function setBusy(isBusy, label) {
    state.busy = isBusy;
    const btn = $('#btn-scan');
    if (btn) {
      btn.disabled = isBusy;
      btn.innerHTML = isBusy
        ? `<span class="spinner"></span><span>Analysing…</span>`
        : `<i data-lucide="shield-alert"></i><span>Scan with XEROX</span>`;
    }
    const status = $('#scan-status');
    if (status && label) status.textContent = label;
    const progress = $('#scan-progress');
    if (progress) {
      progress.classList.toggle('active', isBusy);
      const fill = progress.querySelector('i');
      if (fill) fill.style.width = isBusy ? '55%' : '100%';
    }
    const surface = $('#scan-surface');
    if (surface) surface.classList.toggle('scanning', isBusy);
    if (window.XRUtil) window.XRUtil.refreshIcons();
  }

  function finishProgress() {
    const progress = $('#scan-progress');
    if (progress) {
      const fill = progress.querySelector('i');
      if (fill) fill.style.width = '100%';
      setTimeout(() => { progress.classList.remove('active'); if (fill) fill.style.width = '0%'; }, 550);
    }
    const status = $('#scan-status');
    if (status) status.textContent = 'Scan complete — evidence rendered in the telemetry panel.';
    const surface = $('#scan-surface');
    if (surface) surface.classList.remove('scanning');
  }

  async function doScan(modeOverride) {
    if (state.busy) return;
    const mode = modeOverride || state.mode;
    if (mode === 'url' && !(($('#in-url') && $('#in-url').value.trim()))) {
      if (window.XRUtil) window.XRUtil.toast('Enter a URL first.', 'warn');
      return;
    }
    if (mode === 'code' && !(($('#in-html') && $('#in-html').value.trim()))) {
      if (window.XRUtil) window.XRUtil.toast('Paste the page HTML or JavaScript source first.', 'warn');
      return;
    }
    setBusy(true, mode === 'url' ? 'Resolving DNS + RDAP and computing 16 features…' : mode === 'call' ? 'Evaluating vishing signatures…' : 'Running ensemble analysis…');
    try {
      const payload = await gatherPayload(mode);
      const result = await scan(payload, {
        onStage: (stage) => {
          const status = $('#scan-status');
          if (status) status.textContent = stage === 'dns' ? 'Querying Google DNS-over-HTTPS…' : stage === 'rdap' ? 'Fetching RDAP registration age…' : 'Analysing…';
        }
      });
      if (!result.ok) {
        if (window.XRUtil) window.XRUtil.toast(result.error, 'warn');
        setBusy(false);
        return;
      }
      renderAll(result);
      addLogEntry(result, inputSummaryFor(mode));
      const tabsCard = $('#results-card');
      if (tabsCard) tabsCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
    } catch (err) {
      console.error(err);
      if (window.XRUtil) window.XRUtil.toast('Scan failed: ' + err.message, 'danger');
    } finally {
      setBusy(false);
      finishProgress();
    }
  }

  /* ---------- Presets ---------- */
  function loadPreset(preset, autoScan) {
    if (!preset) return;
    state.mode = preset.mode;
    switchMode(preset.mode);
    const set = (id, val) => { const el = $(id); if (el) el.value = val == null ? '' : val; };
    set('#in-sender', preset.payload.sender || '');
    set('#in-subject', preset.payload.subject || '');
    set('#in-body', preset.payload.body || '');
    set('#in-url', preset.payload.url || '');
    set('#in-html', preset.payload.html || '');
    set('#in-transcript', preset.payload.transcript || '');
    set('#in-caller', preset.tag === 'CALL' ? 'Unknown caller · +91 98••• •••••' : '');
    set('#in-qr-context', preset.payload.qrCaption || '');
    set('#in-ocr-text', '');

    state.qr.payload = preset.payload.qrPayload || '';
    state.qr.ocrText = '';
    if (preset.payload.qrDataUrl) {
      setQrImage(preset.payload.qrDataUrl, { label: 'QR image pre-loaded' });
    } else {
      clearQrImage();
    }
    const payloadBox = $('#qr-payload-input');
    if (payloadBox) payloadBox.value = state.qr.payload;
    const caption = $('#qr-caption-note');
    if (caption) caption.textContent = state.qr.payload
      ? 'Decoded payload is pre-loaded — press Scan to analyse it.'
      : 'Describe what the sender claimed this QR would do.';

    $$('.preset-btn').forEach(b => b.classList.toggle('active', b.getAttribute('data-preset') === preset.id));
    const title = $('#scan-status');
    if (title) title.textContent = `Loaded preset: ${preset.label}`;
    if (window.XRUtil) {
      window.XRUtil.refreshIcons();
      window.XRUtil.toast('Preset loaded — ' + preset.label, preset.expectedTone === 'safe' ? 'safe' : 'danger');
    }
    if (autoScan !== false) setTimeout(() => doScan(preset.mode), 420);
  }

  function renderPresetBars() {
    const presets = window.XEROX_PRESETS || [];
    $$('[data-preset-bar]').forEach(bar => {
      bar.innerHTML = presets.map(p => `<button class="preset-btn" data-preset="${p.id}" title="${esc(p.note)}">
        <i data-lucide="${p.icon}"></i>
        <span>${esc(p.label)}</span>
        <span class="p-type">${esc(p.tag)}</span>
      </button>`).join('');
      bar.addEventListener('click', (e) => {
        const btn = e.target.closest('[data-preset]');
        if (!btn) return;
        const preset = window.getXeroxPreset(btn.getAttribute('data-preset'));
        loadPreset(preset, true);
      });
    });
    if (window.XRUtil) window.XRUtil.refreshIcons();
  }

  /* ---------- Mode switching ---------- */
  function switchMode(mode) {
    state.mode = mode;
    $$('[data-mode]').forEach(btn => btn.classList.toggle('active', btn.getAttribute('data-mode') === mode));
    $$('.mode-panel').forEach(panel => panel.classList.toggle('active', panel.getAttribute('data-panel') === mode));
    const label = $('#active-mode-label');
    if (label) label.textContent = CHANNEL_LABEL[mode] || mode;
    if (window.XRUtil) window.XRUtil.refreshIcons();
  }

  function bindShortcuts() {
    const ORDER = ['text', 'call', 'url', 'qr', 'code'];
    document.addEventListener('keydown', (e) => {
      const t = e.target || {};
      const tag = (t.tagName || '').toLowerCase();
      if (tag === 'input' || tag === 'textarea' || tag === 'select' || t.isContentEditable) return;
      if (e.ctrlKey || e.metaKey || e.altKey) return;
      const n = parseInt(e.key, 10);
      if (n >= 1 && n <= 5 && ORDER[n - 1]) { e.preventDefault(); switchMode(ORDER[n - 1]); }
    });
  }

  function bindModeTabs() {
    $$('[data-mode]').forEach(btn => {
      btn.addEventListener('click', () => switchMode(btn.getAttribute('data-mode')));
    });
  }

  function bindXaiTabs() {
    $$('[data-xai-tab]').forEach(btn => {
      btn.addEventListener('click', () => {
        const target = btn.getAttribute('data-xai-tab');
        $$('[data-xai-tab]').forEach(b => b.classList.toggle('active', b === btn));
        $$('.tab-panel').forEach(p => p.classList.toggle('active', p.id === 'xai-' + target));
        if (window.XRUtil) window.XRUtil.refreshIcons();
      });
    });
  }

  /* ---------- Neural model ---------- */
  function bindNeural() {
    const btn = $('#btn-load-neural');
    if (!btn) return;
    btn.addEventListener('click', async () => {
      const status = $('#neural-status');
      if (!window.NLPEngine) return;
      const current = window.NLPEngine.getNeuralState();
      if (current.ready) {
        if (window.XRUtil) window.XRUtil.toast('DistilBERT neural layer is already active.', 'safe');
        return;
      }
      btn.disabled = true;
      btn.innerHTML = '<span class="spinner"></span><span>Downloading…</span>';
      if (status) status.textContent = 'Fetching ONNX weights from Hugging Face (first run only)…';
      const st = await window.NLPEngine.loadNeuralModel(p => {
        if (status) status.textContent = `Downloading ${p.file || 'model'} — ${p.progress || 0}%`;
      });
      btn.disabled = false;
      if (st.status === 'ready') {
        btn.innerHTML = '<i data-lucide="check"></i><span>Neural layer active</span>';
        btn.classList.add('btn-ghost');
        if (status) status.textContent = 'DistilBERT-phishing ONNX loaded — neural score now blended into message scans.';
        if (window.XRUtil) { window.XRUtil.toast('DistilBERT neural layer ready. Rescan a message to include it.', 'safe'); window.XRUtil.refreshIcons(); }
      } else {
        btn.innerHTML = '<i data-lucide="download"></i><span>Load DistilBERT (67 MB)</span>';
        if (status) status.textContent = 'Neural layer unavailable: ' + (st.error || 'network/CDN blocked').slice(0, 120) + ' — local rule engine still fully active.';
        if (window.XRUtil) window.XRUtil.toast('Neural model could not load. The deterministic engine remains active.', 'warn');
      }
    });
  }

  /* ---------- QR / screenshot stage ---------- */
  function setQrStatus(html) {
    const el = $('#qr-status');
    if (el) el.innerHTML = html;
    if (window.XRUtil) window.XRUtil.refreshIcons();
  }

  function setQrImage(src, opts) {
    opts = opts || {};
    const preview = $('#qr-preview');
    const figure = $('#qr-figure');
    const toolbar = $('#qr-toolbar');
    const stage = $('#qr-stage');
    const drop = $('#qr-dropzone');
    if (!preview) return;
    preview.src = src;
    preview.style.display = 'block';
    state.qr.previewSrc = src;
    if (figure) figure.hidden = false;
    if (toolbar) toolbar.hidden = false;
    if (stage) stage.classList.add('has-image');
    if (drop) drop.style.display = 'none';

    const dims = $('#qr-meta-dims');
    const paint = () => {
      if (!dims) return;
      const w = preview.naturalWidth || 0;
      const h = preview.naturalHeight || 0;
      const kb = Math.max(1, Math.round((src.length * 3) / 4 / 1024));
      dims.innerHTML = w
        ? `<b>${w}×${h}</b> px · ~${kb} KB · ${opts.source || 'local file'}`
        : `image loaded · ${opts.source || 'local file'}`;
    };
    if (preview.complete && preview.naturalWidth) paint();
    else preview.addEventListener('load', paint, { once: true });
    if (opts.label) setQrStatus(`<span class="badge badge-safe"><i data-lucide="image"></i>${esc(opts.label)}</span>`);
  }

  function clearQrImage() {
    const preview = $('#qr-preview');
    const figure = $('#qr-figure');
    const toolbar = $('#qr-toolbar');
    const stage = $('#qr-stage');
    const drop = $('#qr-dropzone');
    if (preview) { preview.style.display = 'none'; preview.removeAttribute('src'); }
    if (figure) figure.hidden = true;
    if (toolbar) toolbar.hidden = true;
    if (stage) stage.classList.remove('has-image', 'is-camera');
    if (drop) drop.style.display = '';
    state.qr.previewSrc = '';
    setQrStatus('No image loaded.');
  }

  /* ---------- QR / OCR wiring ---------- */
  function bindQr() {
    const drop = $('#qr-dropzone');
    const fileInput = $('#qr-file');
    const preview = $('#qr-preview');

    const handleFile = async (file) => {
      if (!file) return;
      if (!/^image\//.test(file.type)) { if (window.XRUtil) window.XRUtil.toast('Choose an image file (PNG/JPG).', 'warn'); return; }
      state.qr.file = file;
      const dataUrl = await new Promise((res, rej) => { const r = new FileReader(); r.onload = () => res(r.result); r.onerror = rej; r.readAsDataURL(file); });
      setQrImage(dataUrl, { source: 'local file' });
      setQrStatus('<span class="loading-dots"><i></i><i></i><i></i></span> Decoding QR…');
      try {
        const decoded = await window.QRBrain.decodeFile(file);
        if (decoded.payload) {
          state.qr.payload = decoded.payload;
          const box = $('#qr-payload-input');
          if (box) box.value = decoded.payload;
          setQrStatus(`<span class="badge badge-safe"><i data-lucide="check"></i>QR decoded · version ${decoded.version}</span>`);
          if (window.XRUtil) { window.XRUtil.toast('QR decoded successfully.', 'safe'); window.XRUtil.refreshIcons(); }
        } else {
          setQrStatus('<span class="badge badge-warn"><i data-lucide="alert-triangle"></i>No QR pattern found — running OCR instead…</span>');
          await runOcr(file);
        }
      } catch (err) {
        setQrStatus(`<span class="badge badge-warn">Decoder unavailable: ${esc(err.message)}</span>`);
      }
    };

    if (fileInput) fileInput.addEventListener('change', (e) => handleFile(e.target.files[0]));
    const stageEl = $('#qr-stage') || drop;
    if (drop) drop.addEventListener('click', () => fileInput && fileInput.click());
    if (stageEl) {
      ['dragenter', 'dragover'].forEach(ev => stageEl.addEventListener(ev, (e) => { e.preventDefault(); stageEl.classList.add('dragover'); }));
      ['dragleave', 'drop'].forEach(ev => stageEl.addEventListener(ev, (e) => { e.preventDefault(); stageEl.classList.remove('dragover'); }));
      stageEl.addEventListener('drop', (e) => { const f = e.dataTransfer.files[0]; handleFile(f); });
    }

    /* Real clipboard paste (the dropzone promises it). A pasted image goes
       straight into the stage; pasted text that looks like a payload fills
       the decoded-payload field. Active only while the QR channel is open. */
    document.addEventListener('paste', (e) => {
      if (state.mode !== 'qr' || !e.clipboardData) return;
      const items = e.clipboardData.items || [];
      for (let i = 0; i < items.length; i++) {
        const it = items[i];
        if (it.kind === 'file' && /^image\//.test(it.type)) {
          const f = it.getAsFile();
          if (f) { e.preventDefault(); handleFile(f); return; }
        }
      }
      const text = (e.clipboardData.getData('text') || '').trim();
      if (text && /^(https?:\/\/|upi:\/\/|bitcoin:|ethereum:)/i.test(text)) {
        e.preventDefault();
        state.qr.payload = text;
        const box = $('#qr-payload-input');
        if (box) box.value = text;
        setQrStatus('<span class="badge badge-amber"><i data-lucide="clipboard-paste"></i>Payload pasted from clipboard</span>');
      }
    });

    const replaceBtn = $('#btn-qr-replace');
    if (replaceBtn) replaceBtn.addEventListener('click', () => fileInput && fileInput.click());
    const removeBtn = $('#btn-qr-remove');
    if (removeBtn) removeBtn.addEventListener('click', () => {
      state.qr.file = null;
      state.qr.payload = '';
      if (fileInput) fileInput.value = '';
      const box = $('#qr-payload-input');
      if (box) box.value = '';
      clearQrImage();
      if (window.XRUtil) window.XRUtil.toast('Image cleared.', 'info');
    });

    const camStart = $('#btn-cam-start');
    const camStop = $('#btn-cam-stop');
    const video = $('#qr-video');
    if (camStart && video) {
      camStart.addEventListener('click', async () => {
        try {
          video.style.display = 'block';
          const sg = $('#qr-stage');
          if (sg) sg.classList.add('is-camera');
          camStart.disabled = true;
          state.qr.camera = await window.QRBrain.startCameraScan(video, async (payload) => {
            state.qr.payload = payload;
            const box = $('#qr-payload-input');
            if (box) box.value = payload;
            const status = $('#qr-status');
            if (status) status.innerHTML = '<span class="badge badge-safe"><i data-lucide="check"></i>QR captured from camera</span>';
            camStart.disabled = false;
            video.style.display = 'none';
            const sg = $('#qr-stage');
            if (sg) sg.classList.remove('is-camera');
            doScan('qr');
          }, (s) => {
            const status = $('#qr-status');
            if (status) status.textContent = s.message;
          });
        } catch (err) {
          camStart.disabled = false;
          if (window.XRUtil) window.XRUtil.toast(err.message, 'danger');
        }
      });
    }
    if (camStop && video) camStop.addEventListener('click', () => {
      if (state.qr.camera) state.qr.camera.stop();
      video.style.display = 'none';
      const sg = $('#qr-stage');
      if (sg) sg.classList.remove('is-camera');
      if (camStart) camStart.disabled = false;
    });

    const ocrInput = $('#ocr-file');
    if (ocrInput) ocrInput.addEventListener('change', (e) => { if (e.target.files[0]) runOcr(e.target.files[0]); });

    const manualPayload = $('#qr-payload-input');
    if (manualPayload) manualPayload.addEventListener('input', () => { state.qr.payload = manualPayload.value.trim(); });
  }

  async function runOcr(file) {
    const status = $('#qr-status');
    if (status) status.innerHTML = '<span class="loading-dots"><i></i><i></i><i></i></span> Loading OCR engine (Tesseract)…';
    try {
      const ocr = await window.QRBrain.ocrImage(file, (p) => {
        if (status) status.textContent = p.message;
      });
      state.qr.ocrText = ocr.text;
      const box = $('#in-ocr-text');
      if (box) box.value = ocr.text;
      if (status) status.innerHTML = `<span class="badge badge-amber"><i data-lucide="scan-text"></i>OCR extracted ${ocr.text.length} chars (${Math.round(ocr.confidence || 0)}% conf.)</span>`;
      if (ocr.text) {
        if (window.XRUtil) window.XRUtil.toast('Screenshot text extracted — scanning…', 'info');
        setTimeout(() => doScan('qr'), 300);
      }
    } catch (err) {
      if (status) status.innerHTML = `<span class="badge badge-danger">OCR failed: ${esc(err.message)}</span>`;
      if (window.XRUtil) window.XRUtil.toast('OCR unavailable: ' + err.message, 'warn');
      if (window.XRUtil) window.XRUtil.refreshIcons();
    }
  }

  /* ---------- Live call wiring ---------- */
  function bindCall() {
    const startBtn = $('#btn-call-start');
    const stopBtn = $('#btn-call-stop');
    const canvas = $('#call-waveform');
    const stream = $('#call-transcript');
    const alert = $('#call-alert');
    const liveScore = $('#call-live-score');
    const feed = $('#call-live-feed');
    if (!startBtn || !window.VoiceGuard) return;

    const support = window.VoiceGuard.speechSupport();
    if (!support.recognition) {
      const warn = $('#call-support-warning');
      if (warn) {
        warn.classList.remove('hidden');
        warn.innerHTML = '<i data-lucide="info"></i><span>This browser lacks the Web Speech API. Use Chrome/Edge for live listening, or paste a transcript below — the analyser works either way.</span>';
      }
    }

    const appendLine = (text, flagged) => {
      if (!stream) return;
      const line = document.createElement('div');
      line.className = 'transcript-line' + (flagged ? ' flagged' : '');
      line.innerHTML = `<span class="ts">${new Date().toTimeString().slice(0, 8)}</span>${esc(text)}`;
      stream.appendChild(line);
      stream.scrollTop = stream.scrollHeight;
    };

    startBtn.addEventListener('click', async () => {
      startBtn.disabled = true;
      try {
        state.call.controller = await window.VoiceGuard.startLive({
          canvas,
          lang: 'en-IN',
          onStatus: (s) => {
            const status = $('#call-status');
            if (status) status.textContent = s.message;
            const ring = $('#listening-ring');
            if (ring) ring.classList.toggle('active', s.status === 'listening');
          },
          onInterim: (text) => {
            if (feed) feed.textContent = text ? '“' + text + '”' : '';
          },
          onFinal: (chunk, all) => {
            appendLine(chunk, false);
            state.call.finalText = all;
            const box = $('#in-transcript');
            if (box) box.value = all;
            if (feed) feed.textContent = '';
          },
          onSignal: (signals, analysis) => {
            if (alert) {
              alert.classList.remove('hidden');
              alert.className = 'alert-strip danger';
              alert.innerHTML = `<i data-lucide="siren"></i><div><strong>SCAM PHRASE DETECTED LIVE — HANG UP.</strong><br>${esc(signals[0].label)}: ${esc(signals[0].detail)}<br><span class="text-xs">${esc(signals[0].advice || '')}</span></div>`;
              if (window.XRUtil) window.XRUtil.refreshIcons();
            }
            if (state.call.controller) state.call.controller.setDanger(true);
            if (window.XRUtil) window.XRUtil.toast('Critical vishing phrase detected in the live call!', 'danger');
          },
          onAnalysis: (analysis) => {
            if (liveScore) {
              liveScore.textContent = analysis.score + '/100';
              liveScore.style.color = scoreColor(analysis.score);
            }
            const badge = $('#call-live-verdict');
            if (badge) {
              badge.className = 'verdict-badge ' + (analysis.score >= 65 ? 'danger' : analysis.score >= 35 ? 'warn' : 'safe');
              badge.textContent = analysis.score >= 65 ? 'FALSE — SCAM CALL' : analysis.score >= 35 ? 'CAUTION' : 'NO SIGNATURE YET';
            }
          }
        });
        stopBtn.disabled = false;
        if (window.XRUtil) window.XRUtil.toast('Live call guardian active — microphone in use.', 'info');
      } catch (err) {
        startBtn.disabled = false;
        if (window.XRUtil) window.XRUtil.toast(err.message, 'danger');
        const status = $('#call-status');
        if (status) status.textContent = err.message;
      }
    });

    if (stopBtn) stopBtn.addEventListener('click', () => {
      window.VoiceGuard.stopLive();
      if (state.call.controller) state.call.controller = null;
      startBtn.disabled = false;
      stopBtn.disabled = true;
      const ring = $('#listening-ring');
      if (ring) ring.classList.remove('active');
      const status = $('#call-status');
      if (status) status.textContent = 'Listener stopped. Transcript retained for analysis.';
      if (state.call.finalText) doScan('call');
    });

    const audioInput = $('#audio-file');
    if (audioInput) audioInput.addEventListener('change', async (e) => {
      const file = e.target.files[0];
      if (!file) return;
      const status = $('#audio-status');
      if (status) status.innerHTML = '<span class="loading-dots"><i></i><i></i><i></i></span> Preparing audio…';
      try {
        const res = await window.VoiceGuard.transcribeAudioFile(file, (p) => { if (status) status.textContent = p.message; });
        const box = $('#in-transcript');
        if (box) box.value = res.text;
        state.call.finalText = res.text;
        if (status) status.innerHTML = `<span class="badge badge-safe"><i data-lucide="check"></i>Transcribed ${Math.round(res.duration)}s via ${esc(res.engine)}${res.truncated ? ' (first 180s)' : ''}</span>`;
        if (res.text) setTimeout(() => doScan('call'), 350);
      } catch (err) {
        if (status) status.innerHTML = `<span class="badge badge-warn">${esc(err.message)}</span>`;
        if (window.XRUtil) window.XRUtil.toast('Audio transcription unavailable: ' + err.message, 'warn');
      }
    });
  }

  /* ---------- Gemini deep check ---------- */
  async function geminiDeepCheck(result) {
    const host = $('#gemini-result');
    const keys = window.XRUtil ? window.XRUtil.getApiKeys() : { gemini: '' };
    if (!keys.gemini) {
      if (host) host.innerHTML = '<div class="alert-strip warn"><i data-lucide="key-round"></i><span>No Gemini key configured. Open <strong>API</strong> in the header to add one — the local engines already produced the verdict above.</span></div>';
      if (window.XRUtil) window.XRUtil.refreshIcons();
      return;
    }
    if (host) host.innerHTML = '<div class="alert-strip info"><i data-lucide="sparkles"></i><span>Contacting Gemini for an independent structured review…</span></div>';

    const payload = result.xai;
    const content = [
      'CHANNEL: ' + result.channelLabel,
      'LOCAL ENSEMBLE SCORE: ' + result.score + '/100 (' + result.verdict.headline + ')',
      result.input && result.input.body ? 'MESSAGE:\n' + String(result.input.body).slice(0, 2600) : '',
      result.input && result.input.url ? 'URL: ' + result.input.url : '',
      result.input && result.input.transcript ? 'CALL TRANSCRIPT:\n' + String(result.input.transcript).slice(0, 2600) : '',
      result.input && result.input.html ? 'WEBPAGE SOURCE (truncated):\n' + String(result.input.html).slice(0, 1800) : '',
      result.input && result.input.qrPayload ? 'QR PAYLOAD: ' + result.input.qrPayload : '',
      result.xai.url ? 'URL FEATURES: ' + result.xai.url.features.map(f => f.key + '=' + f.display).join(', ') : '',
      payload.nlp ? 'NLP TRIGGERS: ' + payload.nlp.triggers.map(t => t.label).join('; ') : ''
    ].filter(Boolean).join('\n\n');

    const prompt = `You are a senior anti-phishing analyst. Independently audit the following submission. Decide whether it is legitimate (TRUE) or a scam/phishing attempt (FALSE), or suspicious (CAUTION).\n\n${content}\n\nReply with ONLY a JSON object, no markdown fences:\n{"verdict":"TRUE|CAUTION|FALSE","risk_score":0-100,"confidence":0.0-1.0,"red_flags":["..."],"reasons":["..."],"advice":"one actionable sentence"}`;

    try {
      const res = await fetch('https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=' + encodeURIComponent(keys.gemini), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ parts: [{ text: prompt }] }],
          generationConfig: { temperature: 0.1, maxOutputTokens: 700, responseMimeType: 'application/json' }
        })
      });
      const json = await res.json();
      if (!res.ok) throw new Error((json.error && json.error.message) || ('HTTP ' + res.status));
      const text = json.candidates && json.candidates[0] && json.candidates[0].content && json.candidates[0].content.parts && json.candidates[0].content.parts[0].text;
      if (!text) throw new Error('Empty response from Gemini.');
      const clean = text.replace(/^```(?:json)?/i, '').replace(/```$/i, '').trim();
      const parsed = JSON.parse(clean);
      const tone = parsed.verdict === 'FALSE' ? 'danger' : parsed.verdict === 'CAUTION' ? 'warn' : 'safe';
      if (host) {
        host.innerHTML = `<div class="alert-strip ${tone}"><i data-lucide="sparkles"></i><div>
          <strong>Gemini independent verdict: ${esc(parsed.verdict)} · ${esc(String(parsed.risk_score))}/100 · confidence ${Math.round((parsed.confidence || 0) * 100)}%</strong><br>
          ${(parsed.reasons || []).slice(0, 3).map(r => '• ' + esc(r)).join('<br>')}
          ${(parsed.red_flags || []).length ? '<br><span class="text-xs">Red flags: ' + parsed.red_flags.slice(0, 4).map(esc).join(', ') + '</span>' : ''}
          <br><span class="text-xs"><strong>Advice:</strong> ${esc(parsed.advice || '')}</span>
        </div></div>`;
        if (window.XRUtil) window.XRUtil.refreshIcons();
      }
    } catch (err) {
      if (host) host.innerHTML = `<div class="alert-strip danger"><i data-lucide="alert-triangle"></i><span>Gemini check failed: ${esc(err.message)} — delete and re-paste the key in the API modal, then retry.</span></div>`;
      if (window.XRUtil) window.XRUtil.refreshIcons();
    }
  }

  /* ============================================================
     PART 4 — QUICK VERIFY (index page)
     ============================================================ */
  function autoDetectMode(value) {
    const v = String(value || '').trim();
    if (/^https?:\/\//i.test(v) || /^www\./i.test(v) || (/^[a-z0-9-]+(\.[a-z0-9-]+)+(\/\S*)?$/i.test(v) && !/\s/.test(v))) return 'url';
    if (/<[a-z!][\s\S]*>/i.test(v)) return 'code';
    return 'text';
  }

  function bindQuickVerify() {
    const input = $('#qv-input');
    const typeSelect = $('#qv-type');
    const button = $('#qv-btn');
    const host = $('#qv-result');
    if (!input || !button || !host) return;

    const run = async () => {
      const value = input.value.trim();
      if (!value) { if (window.XRUtil) window.XRUtil.toast('Paste a message, link or page source first.', 'warn'); return; }
      const selected = typeSelect ? typeSelect.value : 'auto';
      const mode = selected === 'auto' ? autoDetectMode(value) : selected;
      button.disabled = true;
      button.innerHTML = '<span class="spinner"></span> Verifying…';
      host.innerHTML = `<div class="glass-card"><div class="flex items-center gap-2"><span class="loading-dots"><i></i><i></i><i></i></span><span class="text-sm text-muted">Fusing engines for a ${mode === 'url' ? 'live DNS + RDAP' : mode === 'code' ? 'DOM' : 'semantic NLP'} verdict…</span></div></div>`;
      try {
        const payload = mode === 'url' ? { mode, url: value } : mode === 'code' ? { mode, html: value } : { mode, body: value };
        const result = await scan(payload);
        if (!result.ok) throw new Error(result.error);
        host.innerHTML = `<div class="glass-card" style="border-color:${result.verdict.tone === 'danger' ? 'rgba(239, 68, 68, .45)' : result.verdict.tone === 'warn' ? 'rgba(234, 179, 8, .45)' : 'rgba(16, 185, 129, .45)'};">
          <div class="flex items-center justify-between wrap gap-2 mb-2">
            <span class="verdict-badge ${result.verdict.tone} verdict-pop"><i data-lucide="${result.verdict.icon}"></i>${result.verdict.badgeText || result.verdict.headline}</span>
            <span class="mono text-sm" style="color:${scoreColor(result.score)};font-weight:700;">${result.score}/100 risk</span>
          </div>
          <p class="text-sm" style="color:#d6d0c8;">${esc(result.recommendation)}</p>
          <ul class="xai-list" style="margin-top:14px;">
            ${result.evidence.slice(0, 3).map(e => `<li class="${e.tone}"><span class="xi"><i data-lucide="${e.tone === 'danger' ? 'octagon-alert' : e.tone === 'warn' ? 'alert-triangle' : e.tone === 'safe' ? 'check' : 'info'}"></i></span><span>${esc(e.text)}</span></li>`).join('')}
          </ul>
          <div class="flex items-center justify-between wrap gap-2 mt-2">
            <span class="text-xs mono text-faint">${result.latencyMs} ms · ${result.confidence}% confidence · ${result.components.map(c => c.key.toUpperCase() + ' ' + c.score).join(' · ')}</span>
            <a href="scanner.html" class="btn btn-ghost btn-sm">Full breakdown in Scanner <i data-lucide="arrow-right"></i></a>
          </div>
        </div>`;
        if (window.XRUtil) { window.XRUtil.refreshIcons(); window.XRUtil.toast(result.verdict.headline, result.verdict.tone); }
      } catch (err) {
        host.innerHTML = `<div class="alert-strip danger"><i data-lucide="alert-triangle"></i><span>${esc(err.message)}</span></div>`;
        if (window.XRUtil) window.XRUtil.refreshIcons();
      } finally {
        button.disabled = false;
        button.innerHTML = '<i data-lucide="scan-search"></i> Verify now';
        if (window.XRUtil) window.XRUtil.refreshIcons();
      }
    };

    button.addEventListener('click', run);
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey && input.tagName !== 'TEXTAREA') { e.preventDefault(); run(); }
      if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) { e.preventDefault(); run(); }
    });
    $$('[data-qv-preset]').forEach(btn => btn.addEventListener('click', () => {
      const p = window.getXeroxPreset(btn.getAttribute('data-qv-preset'));
      if (!p) return;
      const value = p.payload.url || p.payload.body || p.payload.transcript || '';
      input.value = value;
      if (typeSelect) typeSelect.value = p.mode === 'url' ? 'url' : 'text';
      run();
    }));
  }

  /* ============================================================
     PART 5 — BOOT
     ============================================================ */
  async function patchQrPayloadState() {
    const box = $('#qr-payload-input');
    if (box) state.qr.payload = box.value.trim();
  }

  function boot() {
    /* Quick-verify may exist on any page (index hero). Only the scanner page
       owns the full console, so guard every scanner-only binding. */
    bindQuickVerify();
    renderPresetBars();
    if (!$('#btn-scan')) {
      /* Lean mode: index/architecture pages only need the quick-verify bar. */
      $$('[data-qv-preset]').forEach(b => b.addEventListener('click', () => {
        const pr = window.getXeroxPreset(b.getAttribute('data-qv-preset'));
        if (pr) { const i = $('#qv-input'); if (i) i.value = pr.payload.body || pr.payload.url || pr.payload.transcript || ''; }
      }));
      if (window.XRUtil) window.XRUtil.refreshIcons();
      return;
    }
    bindModeTabs();
    bindShortcuts();
    bindXaiTabs();
    bindLog();
    bindNeural();
    bindQr();
    bindCall();
    patchQrPayloadState();

    const scanBtn = $('#btn-scan');
    if (scanBtn) scanBtn.addEventListener('click', () => doScan());
    const scanAllBtn = $('#btn-scan-all');
    if (scanAllBtn) scanAllBtn.addEventListener('click', () => doScan('all'));
    const resetBtn = $('#btn-reset');
    if (resetBtn) resetBtn.addEventListener('click', () => {
      ['#in-sender', '#in-subject', '#in-body', '#in-url', '#in-html', '#in-transcript', '#in-caller', '#in-qr-context', '#in-ocr-text'].forEach(id => { const el = $(id); if (el) el.value = ''; });
      state.qr.payload = ''; state.qr.ocrText = ''; state.qr.previewSrc = ''; state.call.finalText = '';
      const box = $('#qr-payload-input'); if (box) box.value = '';
      clearQrImage();
      $$('.preset-btn').forEach(b => b.classList.remove('active'));
      const status = $('#scan-status'); if (status) status.textContent = 'Console cleared.';
      if (window.XRUtil) window.XRUtil.toast('Console reset.', 'info');
    });
    const deepBtn = $('#btn-deep-check');
    if (deepBtn) deepBtn.addEventListener('click', () => {
      if (!state.lastResult) { if (window.XRUtil) window.XRUtil.toast('Run a scan first.', 'warn'); return; }
      geminiDeepCheck(state.lastResult);
    });

    /* Ctrl/Cmd+Enter anywhere on the scanner */
    document.addEventListener('keydown', (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'Enter' && $('#btn-scan')) { e.preventDefault(); doScan(); }
    });

    /* Deep-link mode from the footer/query string */
    const params = new URLSearchParams(window.location.search);
    const modeParam = params.get('mode');
    if (modeParam && ['text', 'call', 'url', 'qr', 'code'].includes(modeParam) && $('#btn-scan')) switchMode(modeParam);
    const presetParam = params.get('preset');
    if (presetParam && window.getXeroxPreset) {
      const p = window.getXeroxPreset(presetParam);
      if (p && $('#btn-scan')) setTimeout(() => loadPreset(p, true), 350);
    }

    renderLog();
    if (window.XRUtil) window.XRUtil.refreshIcons();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();

  /* ============================================================
     PUBLIC API
     ============================================================ */
  window.EnsembleBrain = {
    scan,
    BASE_WEIGHTS,
    verdictForScore(score) {
      return score >= 65 ? 'FALSE' : score >= 35 ? 'CAUTION' : 'TRUE';
    }
  };
  window.XEROX = { scan, render: renderAll };
  window.runXeroxEnsembleScan = function (inputPayload) { return scan(inputPayload); };
  /* Back-compat alias retained from the original Catalyst PRD signature */
  window.runCatalystEnsembleScan = window.runXeroxEnsembleScan;
})();
