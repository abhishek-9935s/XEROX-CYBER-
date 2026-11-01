/* ============================================================
   XEROX — voice-call-engine.js  (Module D)
   Real live phone-call guardian:
     • MDN Web Speech API (SpeechRecognition, continuous + interim)
     • Web Audio API AnalyserNode → live canvas waveform
     • Per-sentence vishing detection with instant critical alerts
     • Caller transcript analysis (paste or dictated)
     • Optional real Whisper-tiny transcription of uploaded audio
       through Hugging Face Transformers.js
   ============================================================ */
(function () {
  'use strict';

  const WHISPER_MODEL = 'onnx-community/whisper-tiny.en';
  const TRANSFORMERS_CDN = 'https://cdn.jsdelivr.net/npm/@huggingface/transformers@3.0.0';

  /* ------------------------------------------------------------
     Vishing / phone-fraud signatures (call-specific)
     ------------------------------------------------------------ */
  const CALL_SIGNATURES = [
    {
      id: 'call-remote-access', weight: 14, severity: 'critical',
      label: 'Remote-access app requested',
      detail: 'The caller asked you to install AnyDesk/TeamViewer/RustDesk — they will take control of your phone and banking apps.',
      advice: 'Hang up. Never install remote-access software for an unsolicited caller.',
      re: /\b(anydesk|team\s?viewer|rustdesk|quick\s?support|ultraviewer|ammyy|logmein|splashtop|screen (?:sharing|mirroring))\b/i
    },
    {
      id: 'call-otp-demand', weight: 14, severity: 'critical',
      label: 'OTP demanded over the phone',
      detail: 'They asked you to read aloud / share a 4–8 digit OTP or verification code. This authorises the theft immediately.',
      advice: 'Never read an OTP to anyone. Banks never ask for it on a call.',
      re: /\b(read|tell|say|share|send|give|provide|dictate)\b[^.!?\n]{0,60}\b(otp|o\.t\.p\.?|one[- ]time (?:password|code)|verification code|6[- ]digit|4[- ]digit)\b/i
    },
    {
      id: 'call-pin-to-receive', weight: 14, severity: 'critical',
      label: '"Enter PIN to receive money"',
      detail: 'Receiving money NEVER requires a PIN or UPI approval. Entering it sends money out.',
      advice: 'A UPI PIN only ever debits you. Reject any collect request.',
      re: /\b(enter|type|approve|accept)\b[^.!?\n]{0,50}\b(upi\s?pin|pin|collect request|payment request)\b[^.!?\n]{0,60}\b(receive|refund|credit|money back|cashback)\b|\b(approve|accept)\b[^.!?\n]{0,30}\b(upi|collect|payment) (?:request|notification)\b/i
    },
    {
      id: 'call-digital-arrest', weight: 14, severity: 'critical',
      label: 'Digital-arrest impersonation',
      detail: 'Police / CBI / Customs / Narcotics framing combined with urgency is the "digital arrest" scam. No agency investigates over a call.',
      advice: 'No Indian agency arrests or fines you over a video call. Disconnect and dial 1930.',
      re: /\b(cbi|police|customs|narcotics|enforcement directorate|crime branch|supreme court|warrant|fir|arrest)\b[\s\S]{0,160}?\b(video call|skype|join the call|do not (?:tell|disconnect)|transfer|otp|frozen)\b/i
    },
    {
      id: 'call-freeze-threat', weight: 10, severity: 'high',
      label: 'Account-freeze countdown',
      detail: 'A literal countdown to freezing your account is pure coercion — banks freeze through written process, not phone calls.',
      advice: 'End the call and verify directly with your bank\'s official number.',
      re: /\b(frozen|blocked|closed|suspended)\s+(?:in|within)\s+\d{1,2}\s*(minutes?|hours?)\b|\byour account will be (?:frozen|blocked|debited)\b/i
    },
    {
      id: 'call-isolation', weight: 11, severity: 'high',
      label: 'Isolation instruction',
      detail: 'Being told not to disconnect, not to tell family, or not to visit the branch is designed to stop verification.',
      advice: 'Talk to a family member or your bank immediately. Legitimate staff never ask for secrecy.',
      re: /\b(do not|don'?t|never)\s+(?:tell|inform|involve|contact|disconnect|hang up|cut the call|drop the call)\b[^.!?\n]{0,40}\b(family|anyone|bank|police|call|now|anybody)?/i
    },
    {
      id: 'call-courier', weight: 8, severity: 'high',
      label: 'Fake courier / customs call',
      detail: 'The "parcel in your name was seized" script is the opening line of most digital-arrest calls.',
      advice: 'Track parcels only on the courier\'s official site. Never pay a "clearance fee" by phone.',
      re: /\b(parcel|package|courier|shipment)\b[^.!?\n]{0,80}\b(customs|seized|narcotics|illegal|detained|your name|address)\b/i
    },
    {
      id: 'call-kyc-video', weight: 9, severity: 'high',
      label: 'Fake KYC video verification',
      detail: 'Real KYC is done in-app or at a branch, never on a random video call with an unknown officer.',
      advice: 'Complete KYC only inside your bank\'s official app or at a branch.',
      re: /\b(kyc|re-?kyc|video kyc)\b[\s\S]{0,90}?\b(video call|skype|whatsapp call|complete now|officer|suspend)\b/i
    },
    {
      id: 'call-gift-card', weight: 12, severity: 'critical',
      label: 'Gift-card / crypto payment demand',
      detail: 'Gift cards and crypto are untraceable — no court, tax office or employer accepts them as payment.',
      advice: 'This is a guaranteed scam. Do not buy or transfer anything.',
      re: /\b(gift ?card|itunes|google play card|amazon card|bitcoin|usdt|crypto wallet)\b/i
    },
    {
      id: 'call-refund-remote', weight: 11, severity: 'critical',
      label: 'Refund + screen-share trap',
      detail: 'Fraudsters posing as refund agents share your screen, read the OTP and drain the account.',
      advice: 'Refunds are credited automatically. Never share your screen with a "refund agent".',
      re: /\brefund\b[\s\S]{0,120}?\b(screen|anydesk|teamviewer|otp|pin|scan|remote)\b/i
    },
    {
      id: 'call-army-police', weight: 8, severity: 'high',
      label: 'Agency name-drop',
      detail: 'Invoking CBI / police / TRAI / RBI authority is a persuasion tactic, not proof of identity.',
      advice: 'Ask for the officer\'s station and call it back on a number you look up yourself.',
      re: /\b(cbi|fbi|police|customs|trai|rbi|cyber crime|income tax department)\b/i
    },
    {
      id: 'call-urgent-action', weight: 5, severity: 'medium',
      label: 'Urgency pressure',
      detail: 'Pressure to act immediately is used to prevent you from thinking or verifying.',
      advice: 'Slow down. Real institutions give you time and documentation.',
      re: /\b(immediately|right now|within \d+ (?:minutes|hours)|urgent|last chance|final warning)\b/i
    },
    {
      id: 'call-callback-trap', weight: 6, severity: 'high',
      label: 'Unlisted callback number',
      detail: 'Being pushed to call a number supplied by the caller can route you to a second scammer.',
      advice: 'Only use the number printed on your card or the official app.',
      re: /\bcall (?:me|us) (?:back )?(?:on|at)\b|\bdial this number\b|\bhelpline (?:number )?is\b/i
    }
  ];

  const LEGIT_CALL_PHRASES = [
    { id: 'lc-recorded', label: 'Recorded-line disclosure', weight: 5, re: /\b(this call (?:may be|is) (?:recorded|monitored))\b/i },
    { id: 'lc-verify-official', label: 'Verify via official channel', weight: 6, re: /\b(verify (?:this|the) (?:call|request) (?:by|using)|call the number (?:on|printed))\b/i },
    { id: 'lc-no-charge', label: 'No payment requested', weight: 5, re: /\b(no payment (?:is )?(?:required|needed)|there is no (?:fee|charge))\b/i },
    { id: 'lc-never-share', label: 'Never-share reminder', weight: 6, re: /\b(never share (?:your )?(?:otp|pin|password))\b/i }
  ];

  /* ------------------------------------------------------------
     Transcript analysis
     ------------------------------------------------------------ */
  function detectCallSignals(text) {
    const hits = [];
    CALL_SIGNATURES.forEach(sig => {
      const m = sig.re.exec(text);
      if (m) hits.push({
        id: sig.id, category: 'call', severity: sig.severity, weight: sig.weight,
        label: sig.label, detail: sig.detail, advice: sig.advice,
        text: m[0].slice(0, 120), matchIndex: m.index
      });
    });
    return hits;
  }

  function analyzeTranscript(transcript, caller) {
    const text = String(transcript || '');
    const callerId = caller ? String(caller) : '';
    const base = (window.NLPEngine && window.NLPEngine.analyze)
      ? window.NLPEngine.analyze('Live call transcript', callerId, text)
      : { score: 0, triggers: [], highlightedHtml: text, confidence: 0.5, legitSignals: [], categories: [], reasons: [], stats: {} };

    const callHits = detectCallSignals(text);

    /* Merge call signatures into the trigger set without duplicating NLP ids */
    const triggers = base.triggers.slice();
    callHits.forEach(h => {
      if (!triggers.some(t => t.id === h.id)) {
        triggers.push({
          id: h.id, category: 'call', categoryLabel: 'Vishing signature',
          label: h.label, detail: h.detail, weight: h.weight, text: h.text,
          severity: h.severity === 'critical' ? 'danger' : h.severity === 'high' ? 'danger' : 'warn',
          occurrences: 1, advice: h.advice
        });
      }
    });
    triggers.sort((a, b) => b.weight - a.weight);

    const criticalSignals = callHits.filter(h => h.severity === 'critical');
    const highSignals = callHits.filter(h => h.severity === 'high');

    const legitHits = [];
    LEGIT_CALL_PHRASES.forEach(l => { if (l.re.test(text)) legitHits.push({ id: l.id, label: l.label, weight: l.weight }); });

    let score = base.score;
    if (criticalSignals.length) score = Math.max(score, 90 + Math.min(9, (criticalSignals.length - 1) * 3));
    else if (highSignals.length >= 3) score = Math.max(score, 68);
    else if (highSignals.length) score = Math.max(score, 52);

    const legitReduction = legitHits.reduce((s, l) => s + l.weight, 0);
    score = Math.max(0, Math.min(100, Math.round(score - (criticalSignals.length ? 0 : legitReduction * 0.8))));

    const advice = criticalSignals.length
      ? criticalSignals[0].advice
      : highSignals.length
        ? highSignals[0].advice
        : score >= 35
          ? 'Treat this call as unverified. Hang up and call the institution back on its official number.'
          : 'No active vishing signature detected. Stay cautious with unsolicited calls asking for money or codes.';

    const evidence = [];
    if (criticalSignals.length) evidence.push({ tone: 'danger', text: `${criticalSignals.length} CRITICAL vishing signature(s) detected — this call is a confirmed fraud pattern.` });
    (callHits).slice(0, 4).forEach(h => evidence.push({ tone: h.severity === 'critical' || h.severity === 'high' ? 'danger' : 'warn', text: `${h.label}: ${h.detail}` }));
    base.triggers.filter(t => t.category !== 'call').slice(0, 3).forEach(t => evidence.push({ tone: t.severity, text: `${t.label}: ${t.detail}` }));
    if (legitHits.length) evidence.push({ tone: 'safe', text: 'Legitimate-call language detected: ' + legitHits.map(l => l.label).join(', ') + '.' });
    if (!evidence.length) evidence.push({ tone: 'safe', text: 'No coercion, credential or remote-access language found in this transcript.' });

    const words = (text.trim().match(/\S+/g) || []).length;

    return {
      engine: 'voice-guard-v1',
      channel: 'call',
      score,
      confidence: Math.max(0.5, Math.min(0.98, 0.62 + triggers.length * 0.035 + (criticalSignals.length ? 0.18 : 0))),
      triggers,
      callHits,
      criticalSignals,
      highSignals,
      legitSignals: legitHits,
      highlightedHtml: base.highlightedHtml,
      evidence,
      advice,
      reasons: evidence,
      nlp: base,
      stats: { words, sentences: (text.match(/[.!?]+/g) || []).length + 1, signatures: callHits.length, critical: criticalSignals.length },
      extractedPhones: base.extractedPhones || [],
      extractedUrls: base.extractedUrls || []
    };
  }

  /* ------------------------------------------------------------
     Live microphone guardian
     ------------------------------------------------------------ */
  const liveState = { active: false, recognition: null, stream: null, audioCtx: null, analyser: null, rafId: null, restartTimer: null, transcriptLines: [], danger: false };

  function speechSupport() {
    const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
    return {
      recognition: !!SR,
      microphone: !!(navigator.mediaDevices && navigator.mediaDevices.getUserMedia),
      audioContext: !!(window.AudioContext || window.webkitAudioContext)
    };
  }

  function timeStamp() {
    const d = new Date();
    return d.toTimeString().slice(0, 8);
  }

  function drawWaveform(analyser, canvas, state) {
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    if (canvas.width !== Math.floor(rect.width * dpr) || canvas.height !== Math.floor(rect.height * dpr)) {
      canvas.width = Math.floor(rect.width * dpr);
      canvas.height = Math.floor(rect.height * dpr);
    }
    const data = new Uint8Array(analyser.frequencyBinCount);

    const loop = () => {
      if (!state.active) return;
      state.rafId = requestAnimationFrame(loop);
      analyser.getByteTimeDomainData(data);

      const w = canvas.width, h = canvas.height;
      ctx.clearRect(0, 0, w, h);

      /* grid */
      ctx.strokeStyle = 'rgba(168, 162, 158, 0.10)';
      ctx.lineWidth = 1;
      for (let x = 0; x < w; x += w / 24) {
        ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, h); ctx.stroke();
      }

      const bars = 64;
      const step = Math.floor(data.length / bars);
      const barW = w / bars;
      for (let i = 0; i < bars; i++) {
        let sum = 0;
        for (let j = 0; j < step; j++) sum += Math.abs(data[i * step + j] - 128);
        const amp = Math.min(1, (sum / step) / 42);
        const bh = Math.max(2, amp * h * 0.86);
        const x = i * barW + barW * 0.18;
        const grad = ctx.createLinearGradient(0, h / 2 - bh / 2, 0, h / 2 + bh / 2);
        if (state.danger) { grad.addColorStop(0, 'rgba(239, 68, 68, 0.95)'); grad.addColorStop(1, 'rgba(239, 68, 68, 0.35)'); }
        else { grad.addColorStop(0, 'rgba(245, 158, 11, 0.95)'); grad.addColorStop(1, 'rgba(249, 115, 22, 0.4)'); }
        ctx.fillStyle = grad;
        const y = (h - bh) / 2;
        const r = Math.min(3 * dpr, barW / 2);
        ctx.beginPath();
        if (ctx.roundRect) ctx.roundRect(x, y, barW * 0.64, bh, r); else ctx.rect(x, y, barW * 0.64, bh);
        ctx.fill();
      }
    };
    loop();
  }

  async function startLive(opts) {
    opts = opts || {};
    const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (!SR) throw new Error('Live speech recognition is not supported in this browser. Use Chrome or Edge, or paste a transcript instead.');
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) throw new Error('Microphone access is unavailable in this browser.');

    if (liveState.active) stopLive();

    const stream = await navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: true, noiseSuppression: true } });
    const AudioCtx = window.AudioContext || window.webkitAudioContext;
    const audioCtx = new AudioCtx();
    if (audioCtx.state === 'suspended') { try { await audioCtx.resume(); } catch (e) {} }
    const source = audioCtx.createMediaStreamSource(stream);
    const analyser = audioCtx.createAnalyser();
    analyser.fftSize = 2048;
    analyser.smoothingTimeConstant = 0.75;
    source.connect(analyser);

    Object.assign(liveState, { active: true, stream, audioCtx, analyser, transcriptLines: [], danger: false });

    if (opts.canvas) drawWaveform(analyser, opts.canvas, liveState);

    const recognition = new SR();
    recognition.continuous = true;
    recognition.interimResults = true;
    recognition.lang = opts.lang || 'en-IN';
    recognition.maxAlternatives = 1;

    let finalText = '';

    recognition.onstart = () => {
      if (opts.onStatus) opts.onStatus({ status: 'listening', message: 'Listening… put the suspicious caller on speakerphone.' });
    };

    recognition.onresult = (event) => {
      let interim = '';
      for (let i = event.resultIndex; i < event.results.length; i++) {
        const result = event.results[i];
        const chunk = result[0].transcript.trim();
        if (result.isFinal) {
          finalText += ' ' + chunk;
          liveState.transcriptLines.push({ ts: timeStamp(), text: chunk, final: true });
          if (opts.onFinal) opts.onFinal(chunk, finalText.trim());
          /* Real-time re-scoring of the cumulative transcript */
          const analysis = analyzeTranscript(finalText.trim(), opts.caller || '');
          if (analysis.criticalSignals.length && opts.onSignal) {
            liveState.danger = true;
            opts.onSignal(analysis.criticalSignals, analysis);
          }
          if (opts.onAnalysis) opts.onAnalysis(analysis);
        } else {
          interim += chunk;
        }
      }
      if (opts.onInterim) opts.onInterim(interim);
    };

    recognition.onerror = (event) => {
      const map = {
        'not-allowed': 'Microphone permission was denied. Allow mic access and try again.',
        'service-not-allowed': 'Speech service blocked by the browser. Paste a transcript instead.',
        'network': 'Speech recognition needs a network connection (Chrome streams audio to Google). Paste a transcript instead.',
        'audio-capture': 'No microphone was found.',
        'aborted': 'Recognition stopped.',
        'no-speech': 'No speech detected — still listening.'
      };
      if (opts.onStatus) opts.onStatus({ status: event.error === 'no-speech' ? 'listening' : 'error', message: map[event.error] || ('Speech error: ' + event.error) });
    };

    recognition.onend = () => {
      if (liveState.active) {
        /* Chrome ends recognition on silence — restart while the session is active */
        liveState.restartTimer = setTimeout(() => {
          if (!liveState.active) return;
          try { recognition.start(); } catch (e) { /* already started */ }
        }, 320);
      } else if (opts.onStatus) {
        opts.onStatus({ status: 'stopped', message: 'Listening stopped.' });
      }
    };

    try { recognition.start(); } catch (e) {
      stopLive();
      throw new Error('Could not start speech recognition: ' + e.message);
    }
    liveState.recognition = recognition;

    return {
      stop: stopLive,
      setDanger: (val) => { liveState.danger = !!val; },
      isActive: () => liveState.active,
      getTranscript: () => finalText.trim()
    };
  }

  function stopLive() {
    liveState.active = false;
    if (liveState.restartTimer) { clearTimeout(liveState.restartTimer); liveState.restartTimer = null; }
    if (liveState.rafId) { cancelAnimationFrame(liveState.rafId); liveState.rafId = null; }
    if (liveState.recognition) {
      try { liveState.recognition.onend = null; liveState.recognition.stop(); } catch (e) {}
      liveState.recognition = null;
    }
    if (liveState.stream) { liveState.stream.getTracks().forEach(t => t.stop()); liveState.stream = null; }
    if (liveState.audioCtx) { try { liveState.audioCtx.close(); } catch (e) {} liveState.audioCtx = null; }
    liveState.analyser = null;
  }

  /* ------------------------------------------------------------
     Whisper (real audio-file transcription, lazy + optional)
     ------------------------------------------------------------ */
  let whisperPipe = null;
  let whisperLoading = null;
  const whisperState = { status: 'idle', progress: 0, file: '', error: null, model: WHISPER_MODEL };

  async function loadWhisper(onProgress) {
    if (whisperPipe) return whisperPipe;
    if (whisperLoading) return whisperLoading;
    whisperState.status = 'loading';
    whisperLoading = (async () => {
      try {
        const mod = await import(TRANSFORMERS_CDN);
        mod.env.allowLocalModels = false;
        if (mod.env.backends && mod.env.backends.onnx && mod.env.backends.onnx.wasm) mod.env.backends.onnx.wasm.numThreads = 1;
        const progress = (p) => {
          if (p && p.status === 'progress' && typeof p.progress === 'number') {
            whisperState.progress = Math.round(p.progress);
            whisperState.file = p.file || '';
            if (onProgress) onProgress(Object.assign({}, whisperState));
          }
        };
        try {
          whisperPipe = await mod.pipeline('automatic-speech-recognition', WHISPER_MODEL, { dtype: 'q8', progress_callback: progress });
        } catch (e) {
          whisperPipe = await mod.pipeline('automatic-speech-recognition', WHISPER_MODEL, { progress_callback: progress });
        }
        whisperState.status = 'ready';
        whisperState.progress = 100;
        return whisperPipe;
      } catch (e) {
        whisperState.status = 'unavailable';
        whisperState.error = e.message || String(e);
        whisperLoading = null;
        throw e;
      }
    })();
    return whisperLoading;
  }

  async function resampleTo16k(arrayBuffer) {
    const AudioCtx = window.AudioContext || window.webkitAudioContext;
    const ctx = new AudioCtx();
    const decoded = await ctx.decodeAudioData(arrayBuffer.slice(0));
    const duration = decoded.duration;
    const capped = Math.min(duration, 180);
    const targetRate = 16000;
    const frames = Math.ceil(capped * targetRate);
    const OfflineCtx = window.OfflineAudioContext || window.webkitOfflineAudioContext;
    const offline = new OfflineCtx(1, frames, targetRate);
    const src = offline.createBufferSource();
    src.buffer = decoded;
    src.connect(offline.destination);
    src.start(0);
    const rendered = await offline.startRendering();
    const float32 = rendered.getChannelData(0);
    try { ctx.close(); } catch (e) {}
    return { float32, duration, capped, truncated: duration > 180 };
  }

  async function transcribeAudioFile(file, onProgress) {
    if (!file) throw new Error('No audio file provided.');
    const arrayBuffer = await file.arrayBuffer();
    if (onProgress) onProgress({ stage: 'decode', progress: 0, message: 'Decoding audio…' });
    const { float32, duration, truncated } = await resampleTo16k(arrayBuffer);
    if (onProgress) onProgress({ stage: 'model', progress: 0, message: 'Loading Whisper-tiny (first run downloads ~40 MB)…' });
    const pipe = await loadWhisper(p => {
      if (onProgress) onProgress({ stage: 'model', progress: p.progress, message: 'Downloading Whisper weights… ' + p.progress + '%' });
    });
    if (onProgress) onProgress({ stage: 'transcribe', progress: 90, message: 'Transcribing on-device…' });
    const out = await pipe(float32, { sampling_rate: 16000, chunk_length_s: 30, stride_length_s: 5 });
    const text = Array.isArray(out) ? out.map(o => o.text).join(' ') : out.text;
    if (onProgress) onProgress({ stage: 'done', progress: 100, message: 'Transcription complete.' });
    return { text: (text || '').trim(), duration, truncated, engine: 'whisper-tiny.en (transformers.js)', model: WHISPER_MODEL };
  }

  /* ------------------------------------------------------------ */
  window.VoiceGuard = {
    analyzeTranscript,
    detectCallSignals,
    startLive,
    stopLive,
    speechSupport,
    loadWhisper,
    transcribeAudioFile,
    getWhisperState: () => Object.assign({}, whisperState, { ready: whisperState.status === 'ready' }),
    isLive: () => liveState.active,
    SIGNATURE_COUNT: CALL_SIGNATURES.length
  };
  window.analyzeCallTranscript = analyzeTranscript;
})();
