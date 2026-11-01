/* ============================================================
   XEROX — qr-image-engine.js  (Module E)
   Real QR ("quishing") decoding with jsQR + screenshot OCR with
   Tesseract.js. Understands UPI payment traps and forwards any
   decoded URL into url-network-engine.js for live verification.
   ============================================================ */
(function () {
  'use strict';

  const JSQR_CDN = 'https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js';
  const TESSERACT_CDN = 'https://cdn.jsdelivr.net/npm/tesseract.js@5/dist/tesseract.min.js';

  const scriptCache = {};

  function loadScript(src) {
    if (scriptCache[src]) return scriptCache[src];
    scriptCache[src] = new Promise((resolve, reject) => {
      const existing = document.querySelector('script[src="' + src + '"]');
      if (existing) {
        if (existing.dataset.loaded === 'true') return resolve();
        existing.addEventListener('load', () => resolve());
        existing.addEventListener('error', () => reject(new Error('Failed to load ' + src)));
        return;
      }
      const s = document.createElement('script');
      s.src = src;
      s.async = true;
      s.onload = () => { s.dataset.loaded = 'true'; resolve(); };
      s.onerror = () => reject(new Error('Could not load library: ' + src + ' (offline?)'));
      document.head.appendChild(s);
    });
    return scriptCache[src];
  }

  async function ensureJsQR() {
    if (window.jsQR) return window.jsQR;
    await loadScript(JSQR_CDN);
    if (!window.jsQR) throw new Error('jsQR failed to initialise.');
    return window.jsQR;
  }

  async function ensureTesseract() {
    if (window.Tesseract) return window.Tesseract;
    await loadScript(TESSERACT_CDN);
    if (!window.Tesseract) throw new Error('Tesseract.js failed to initialise.');
    return window.Tesseract;
  }

  /* ------------------------------------------------------------
     Image helpers
     ------------------------------------------------------------ */
  function loadImageElement(src) {
    return new Promise((resolve, reject) => {
      const img = new Image();
      img.crossOrigin = 'anonymous';
      img.onload = () => resolve(img);
      img.onerror = () => reject(new Error('Could not read that image.'));
      img.src = src;
    });
  }

  function fileToDataURL(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = () => reject(new Error('Could not read the selected file.'));
      reader.readAsDataURL(file);
    });
  }

  function drawToCanvas(img, scale) {
    const maxSide = 1600;
    let w = img.naturalWidth || img.width;
    let h = img.naturalHeight || img.height;
    const factor = Math.min(scale || 1, maxSide / Math.max(w, h));
    w = Math.max(1, Math.round(w * factor));
    h = Math.max(1, Math.round(h * factor));
    const canvas = document.createElement('canvas');
    canvas.width = w; canvas.height = h;
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    ctx.drawImage(img, 0, 0, w, h);
    return { canvas, ctx, w, h };
  }

  /* Try several scales/inversions — small WhatsApp-forwarded QRs are stubborn */
  async function decodeImageSource(src) {
    const img = await loadImageElement(src);
    const jsQR = await ensureJsQR();
    const attempts = [1, 2, 1.6, 0.7];
    for (const scale of attempts) {
      const { ctx, w, h } = drawToCanvas(img, scale);
      const data = ctx.getImageData(0, 0, w, h);
      const result = jsQR(data.data, w, h, { inversionAttempts: 'attemptBoth' });
      if (result && result.data) {
        return { payload: result.data.trim(), width: w, height: h, version: result.version, image: img };
      }
    }
    return { payload: null, image: img };
  }

  /* ------------------------------------------------------------
     UPI parsing & fraud logic
     ------------------------------------------------------------ */
  function parseUPI(payload) {
    let query = '';
    try {
      const u = new URL(payload);
      query = u.search || '';
    } catch (e) {
      const qIndex = payload.indexOf('?');
      query = qIndex > -1 ? payload.slice(qIndex) : '';
    }
    const params = new URLSearchParams(query);
    const amountRaw = params.get('am') || params.get('amount') || '';
    const amount = amountRaw ? Number(amountRaw) : null;
    return {
      scheme: 'upi',
      vpa: params.get('pa') || params.get('vpa') || '',
      payeeName: params.get('pn') || '',
      amount: Number.isFinite(amount) ? amount : null,
      currency: params.get('cu') || 'INR',
      note: params.get('tn') || params.get('tr') || '',
      merchantCode: params.get('mc') || '',
      transactionRef: params.get('tr') || '',
      raw: payload
    };
  }

  function analyzeUPI(payload, context) {
    const upi = parseUPI(payload);
    const contextText = String(context || '');
    const combined = (contextText + ' ' + upi.note + ' ' + upi.payeeName).toLowerCase();

    const flags = [];
    let score = 28; /* a UPI QR is inherently an outgoing-payment request */

    flags.push({
      id: 'upi-debit-nature', tone: 'info',
      label: 'UPI QR = money OUT',
      detail: 'Scanning a upi://pay QR creates a debit from YOUR account. It can never credit money to you.'
    });

    const receiveClaim = /\b(receive|receiving|refund|refunds|cashback|credit|prize|reward|receive money|money back|incoming)\b/.test(combined);
    if (receiveClaim) {
      score = 95;
      flags.push({
        id: 'upi-receive-lie', tone: 'danger',
        label: '"Scan to RECEIVE money" claim',
        detail: 'The caption claims you will receive money. That is impossible with a pay QR — this is the exact UPI refund scam.'
      });
    }

    if (upi.amount && upi.amount > 0) {
      score += receiveClaim ? 0 : 12;
      flags.push({
        id: 'upi-amount', tone: 'warn',
        label: 'Fixed debit amount in QR',
        detail: 'The QR pre-fills ₹' + upi.amount.toLocaleString('en-IN') + ' — you would pay this exact amount if you approve.'
      });
    }

    if (/refund|support|help|verify|kyc|prize|reward|lucky|winner|lottery|recovery/i.test(upi.vpa + ' ' + upi.payeeName)) {
      score += 6;
      flags.push({
        id: 'upi-suspicious-handle', tone: 'danger',
        label: 'Suspicious payee identity',
        detail: 'Payee "' + (upi.payeeName || upi.vpa) + '" uses refund/verification keywords rather than a registered merchant name.'
      });
    }

    if (!upi.vpa) {
      score += 15;
      flags.push({ id: 'upi-no-vpa', tone: 'danger', label: 'Malformed UPI payload', detail: 'No payee address (pa=) found — the QR cannot be a genuine merchant code.' });
    }

    if (!upi.merchantCode) {
      score += 3;
      flags.push({ id: 'upi-no-mc', tone: 'warn', label: 'No merchant code', detail: 'Personal UPI handles have no merchant category code — normal for a friend, high-risk from a stranger.' });
    }

    score = Math.max(0, Math.min(100, Math.round(score)));

    const evidence = flags.map(f => ({ tone: f.tone === 'danger' ? 'danger' : f.tone === 'warn' ? 'warn' : 'info', text: f.label + ': ' + f.detail }));

    return {
      engine: 'qr-upi-v1',
      channel: 'qr',
      type: 'upi',
      score,
      confidence: 0.92,
      payload,
      upi,
      flags,
      evidence,
      advice: receiveClaim
        ? 'STOP. Never scan a QR to receive money. Ask for a normal bank transfer and verify the sender independently.'
        : 'Only approve this UPI request if you personally know the payee and the amount matches a purchase you initiated.',
      triggers: flags.filter(f => f.tone === 'danger' || f.tone === 'warn').map(f => ({
        id: f.id, category: 'qr', categoryLabel: 'QR / UPI analysis',
        label: f.label, detail: f.detail, weight: f.tone === 'danger' ? 10 : 5,
        text: f.label, severity: f.tone === 'danger' ? 'danger' : 'warn'
      }))
    };
  }

  /* ------------------------------------------------------------
     Payload router
     ------------------------------------------------------------ */
  async function analyzePayload(payload, opts) {
    opts = opts || {};
    const value = String(payload || '').trim();
    if (!value) {
      return { engine: 'qr-router', channel: 'qr', type: 'empty', score: 10, valid: false, evidence: [{ tone: 'warn', text: 'No payload decoded.' }], advice: 'Try a sharper image or enter the QR contents manually.' };
    }

    if (/^upi:\/\//i.test(value)) {
      return analyzeUPI(value, opts.context);
    }

    if (/^https?:\/\//i.test(value) || /^www\./i.test(value) || /^[a-z0-9-]+(\.[a-z0-9-]+)+(\/|$)/i.test(value)) {
      const urlResult = (window.URLBrain && window.URLBrain.analyzeUrlFull)
        ? await window.URLBrain.analyzeUrlFull(value, { onStage: opts.onStage })
        : null;
      if (urlResult) {
        return Object.assign({}, urlResult, {
          channel: 'qr',
          type: 'url',
          qrPayload: value,
          advice: urlResult.score >= 65
            ? 'Do not open this link. The QR redirects to infrastructure our live DNS/RDAP checks flag as dangerous.'
            : 'The decoded link passed structural checks, but only open it if you expected this QR.'
        });
      }
      return { engine: 'qr-router', channel: 'qr', type: 'url', score: 55, qrPayload: value, valid: true, evidence: [{ tone: 'warn', text: 'URL decoded, but the URL engine is unavailable.' }], advice: 'Treat with caution.' };
    }

    const tel = /^tel:/i.test(value);
    const sms = /^smsto:|^sms:/i.test(value);
    if (tel || sms) {
      return {
        engine: 'qr-router', channel: 'qr', type: 'tel', score: 45, valid: true, qrPayload: value,
        evidence: [{ tone: 'warn', text: 'QR dials a phone number: ' + value.replace(/^(tel|sms|smsto):/i, '') + ' — scams often route victims to a fake helpline.' }],
        advice: 'Never call a number supplied by an unsolicited QR. Use the number on your card or official app.',
        triggers: [{ id: 'qr-tel', category: 'qr', categoryLabel: 'QR analysis', label: 'QR opens a phone dialer', detail: 'Fake helpline routing.', weight: 6, text: value, severity: 'warn' }]
      };
    }

    if (/^wifi:/i.test(value)) {
      return {
        engine: 'qr-router', channel: 'qr', type: 'wifi', score: 18, valid: true, qrPayload: value,
        evidence: [{ tone: 'info', text: 'Wi-Fi join code. Only join networks you trust — an attacker hotspot can intercept traffic.' }],
        advice: 'Join only if you trust the network owner.'
      };
    }

    /* Plain text / phone number payload → run the NLP engine */
    const nlp = (window.NLPEngine && window.NLPEngine.analyze) ? window.NLPEngine.analyze('QR text payload', '', value) : null;
    const looksLikePhone = /^(?:\+?\d[\d\s-]{7,15})$/.test(value);
    const score = looksLikePhone ? Math.max(50, nlp ? nlp.score : 0) : (nlp ? nlp.score : 20);
    return {
      engine: 'qr-router', channel: 'qr', type: 'text', score, valid: true,
      qrPayload: value,
      evidence: looksLikePhone
        ? [{ tone: 'warn', text: 'The QR contains only a phone number (' + value + ') — a common "call this helpline" scam vector.' }]
        : (nlp ? nlp.reasons : []),
      triggers: nlp ? nlp.triggers : [],
      advice: looksLikePhone ? 'Do not call numbers from unsolicited QRs.' : (score >= 60 ? 'Treat this QR content as a scam message.' : 'Content appears benign, but verify the source.'),
      nlp
    };
  }

  /* ------------------------------------------------------------
     Screenshot OCR
     ------------------------------------------------------------ */
  function preprocessForOCR(img) {
    const { canvas, ctx, w, h } = drawToCanvas(img, Math.min(2, 1800 / Math.max(img.naturalWidth || img.width, 1)));
    const imageData = ctx.getImageData(0, 0, w, h);
    const d = imageData.data;
    /* grayscale + contrast stretch (helps WhatsApp screenshots) */
    let min = 255, max = 0;
    const gray = new Uint8ClampedArray(w * h);
    for (let i = 0, p = 0; i < d.length; i += 4, p++) {
      const g = Math.round(0.299 * d[i] + 0.587 * d[i + 1] + 0.114 * d[i + 2]);
      gray[p] = g;
      if (g < min) min = g;
      if (g > max) max = g;
    }
    const range = Math.max(1, max - min);
    for (let i = 0, p = 0; i < d.length; i += 4, p++) {
      const stretched = Math.min(255, Math.max(0, ((gray[p] - min) / range) * 255));
      d[i] = d[i + 1] = d[i + 2] = stretched;
    }
    ctx.putImageData(imageData, 0, 0);
    return canvas;
  }

  async function ocrImage(file, onProgress) {
    const Tesseract = await ensureTesseract();
    if (onProgress) onProgress({ stage: 'preprocess', message: 'Enhancing screenshot…' });
    const src = typeof file === 'string' ? file : await fileToDataURL(file);
    const img = await loadImageElement(src);
    const canvas = preprocessForOCR(img);
    if (onProgress) onProgress({ stage: 'ocr', message: 'Reading text (Tesseract OCR)…' });
    const result = await Tesseract.recognize(canvas, 'eng', {
      logger: (m) => {
        if (onProgress && m && m.status === 'recognizing text') onProgress({ stage: 'ocr', progress: Math.round((m.progress || 0) * 100), message: 'Reading text… ' + Math.round((m.progress || 0) * 100) + '%' });
      },
      workerPath: 'https://cdn.jsdelivr.net/npm/tesseract.js@5/dist/worker.min.js',
      corePath: 'https://cdn.jsdelivr.net/npm/tesseract.js-core@5',
      langPath: 'https://tessdata.projectnaptha.com/4.0.0'
    });
    const text = (result && result.data && result.data.text || '').trim();
    return { text, confidence: result && result.data ? result.data.confidence : null, engine: 'tesseract.js', image: img };
  }

  /* ------------------------------------------------------------
     Live camera decoding
     ------------------------------------------------------------ */
  async function startCameraScan(videoEl, onResult, onStatus) {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) throw new Error('Camera access is unavailable in this browser.');
    const jsQR = await ensureJsQR();
    const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: 'environment' }, width: { ideal: 1280 }, height: { ideal: 720 } }, audio: false });
    videoEl.srcObject = stream;
    videoEl.setAttribute('playsinline', 'true');
    await videoEl.play();

    let active = true;
    let rafId = null;
    let lastScan = 0;
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d', { willReadFrequently: true });

    const tick = (ts) => {
      if (!active) return;
      rafId = requestAnimationFrame(tick);
      if (ts - lastScan < 180) return;
      lastScan = ts;
      if (!videoEl.videoWidth) return;
      canvas.width = videoEl.videoWidth;
      canvas.height = videoEl.videoHeight;
      ctx.drawImage(videoEl, 0, 0, canvas.width, canvas.height);
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const code = jsQR(imageData.data, canvas.width, canvas.height, { inversionAttempts: 'dontInvert' });
      if (code && code.data) {
        stop();
        if (onResult) onResult(code.data.trim());
      }
    };

    const stop = () => {
      active = false;
      if (rafId) cancelAnimationFrame(rafId);
      stream.getTracks().forEach(t => t.stop());
      try { videoEl.pause(); } catch (e) {}
      videoEl.srcObject = null;
      if (onStatus) onStatus({ status: 'stopped', message: 'Camera stopped.' });
    };

    if (onStatus) onStatus({ status: 'scanning', message: 'Point the camera at a QR code…' });
    rafId = requestAnimationFrame(tick);
    return { stop, isActive: () => active };
  }

  /* ------------------------------------------------------------
     Public API
     ------------------------------------------------------------ */
  window.QRBrain = {
    decodeImageSource,
    decodeFile: async (file) => {
      const dataUrl = await fileToDataURL(file);
      const res = await decodeImageSource(dataUrl);
      return Object.assign({}, res, { dataUrl });
    },
    analyzePayload,
    parseUPI,
    analyzeUPI,
    ocrImage,
    startCameraScan,
    preprocessForOCR,
    libs: { ensureJsQR, ensureTesseract }
  };
})();
