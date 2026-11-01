# 🛡️ XEROX

**Omni-channel, real-time AI scam & phishing verification — built for the Catalyst Competition.**

XEROX answers one question in milliseconds: **is this TRUE (legitimate) or FALSE (a scam)?** — across
emails and SMS, live phone calls, URLs, QR codes, screenshots and raw webpage code.

Everything runs **client-side in the browser**. No backend, no build step, no npm install, no API key required
(though optional Gemini / Google Safe Browsing keys can be layered on top).

### Brand & theme

| Token | Value | Role |
|---|---|---|
| `--bg-primary` | `#171310` | warm charcoal "light black" canvas |
| `--bg-surface` / `-2` / `-3` | `#221d19` / `#2e2823` / `#453d36` | raised panels and inputs |
| `--accent-orange` | `#f97316` | primary brand / active state |
| `--accent-amber` | `#fbbf24` | secondary highlight |
| `--status-safe` | `#10b981` | TRUE verdict |
| `--status-warn` | `#eab308` | CAUTION verdict (yellow, kept clear of brand orange) |
| `--status-danger` | `#ef4444` | FALSE verdict |

JS/ID namespace: `xr-` classes, `XRUtil`, `XEROX_PRESETS`, `getXeroxPreset`, `runXeroxEnsembleScan`
(a back-compat `runCatalystEnsembleScan` alias is also exported).

> **Trademark note:** XEROX is a registered trademark of Xerox Corporation. This build uses the name for a
> class/competition project. If it ever ships publicly, rename it (e.g. "Xerox" → "X-Shield", "Oxide") or secure
> permission first.

---

## 1. Quick start (works in VS Code)

### Option A — just double-click `index.html`
Everything runs from `file://`. No server required.

### Option B — VS Code Live Server (recommended)
1. Open the **`xerox-website`** folder itself in VS Code (`File → Open Folder`) — not its parent.
2. Right-click **`index.html`** → **Open with Live Server**.
3. It serves on `http://127.0.0.1:5500/index.html`.

> **If Live Server shows a file listing or 404s:** you opened the parent folder, so the address is
> `/xerox-website/index.html` instead of `/index.html`. Right-click inside the `xerox-website` folder's
> `index.html` and re-run Live Server, or add `/xerox-website/` to the URL.

### Option C — plain Python
```bash
cd xerox-website
python3 -m http.server 8000
# → http://localhost:8000
```

### What works with and without internet

| Feature | Offline (`file://` / no wifi) | Online |
|---|---|---|
| Layout, theme, living background | ✅ | ✅ |
| All 56+ icons | ✅ vendored in `js/vendor/lucide.min.js` | ✅ |
| Typography | ✅ self-hosted in `fonts/` | ✅ (Google Fonts used when reachable) |
| Message/URL/DOM/QR engines | ✅ pure JS | ✅ |
| Scanner presets (all 8) | ✅ | ✅ |
| Live DNS-over-HTTPS + RDAP | ⚠️ needs internet | ✅ |
| DistilBERT / Tesseract / jsQR models | ⚠️ downloaded on demand | ✅ |

**No JavaScript CDN is required any more.** Tailwind was removed (it was only supplying four utility
classes that now live in `main.css`), and Lucide is vendored locally.

### Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Blank white page | Opened `index.html` from inside a downloaded `.zip` | Extract the zip first, then open |
| No icons / no styling | Only the `.html` file was copied, without `css/`, `js/`, `fonts/` | Keep the folder structure intact |
| File listing instead of the site | Live Server rooted at the parent folder | Serve from inside `xerox-website/` |
| Icons missing but layout fine | An old copy without `js/vendor/` | Re-copy the whole folder |
| Live DNS/RDAP panel says "unavailable" | Offline, or the network blocks `dns.google` / `rdap.org` | Expected — the local verdict still completes |
| `localhost:5500` connection refused | Live Server extension not running | Install "Live Server" (Ritwick Dey) and click **Go Live** |

---

## 2. The four pillars

| Pillar | What it is | Where to see it |
|---|---|---|
| **The Shield** | Real-time omni-channel barrier with a live risk gauge and quarantine log | `scanner.html` |
| **The Brain** | Semantic intent NLP + URL structure + DOM inspection (not grammar checks) | `architecture.html` |
| **The Tech Stack** | DistilBERT × Random Forest × live DNS/RDAP × Web Speech fused by a meta-scorer | `architecture.html#stack` |
| **The Training** | PhishTank + Multi-Source dataset + SpamAssassin, tuned with a live threshold lab | `training.html` |

---

### 2.1 Scanner console behaviour

| Interaction | What happens |
|---|---|
| **Click / drop** on the QR stage | Accepts any image; the stage swaps to the preview and reports `W×H px · KB · source` |
| **Ctrl/⌘ + V** (QR channel open) | Pastes a screenshot straight from the clipboard; pasting a `upi://`, `http(s)://`, `bitcoin:` or `ethereum:` string fills the decoded-payload field |
| **Replace / Remove** | Re-opens the file picker, or clears the image, payload and status in one click |
| **Webcam** | jsQR scans frames live; the first decode stops the camera and runs the scan |
| **Keys 1–5** | Switch channel (Message, Voice, URL, QR, Code) — ignored while typing in a field |
| **Ctrl/⌘ + Enter** | Run the scan from anywhere on the page |
| **Desktop ≥1025×900** | The telemetry column sticks below the navbar while the console scrolls, so the verdict stays visible |

The QR image is shown at its natural aspect ratio (max 286px tall) on a gridded stage; it is
**not** cropped or upscaled, so a scanned screenshot stays readable.

## 3. File map (23 files)

```
xerox-website/
├── index.html                    # Executive hub, hero pipeline, instant quick-verify, 4-pillar grid
├── scanner.html                  # The Shield — 5-mode verification command centre + quarantine log
├── architecture.html             # The Brain — 3-vector bento, ensemble diagram, weight simulator
├── training.html                 # The Training — datasets, calibration lab, comparison matrix
│
├── css/
│   ├── main.css                  # Design tokens, dark theme, typography, layout, nav, footer
│   ├── components.css            # Glass cards, verdict banners, gauges, code inspector, tables, scanner UI
│   ├── animations.css            # radarScan, pulseGlow, packetFlow, codeScan, reveals, reduced-motion
│   └── background.css            # Living aurora orbs, palette tokens, control pill
│
├── fonts/                        # Self-hosted variable fonts (offline-safe)
│   ├── inter-var.ttf
│   ├── space-grotesk-var.ttf
│   └── jetbrains-mono-var.ttf
│
├── js/
│   ├── navbar.js                 # Shared sticky nav, mobile drawer, footer, API-key modal, utilities
│   ├── background-cycler.js      # 100-palette colour engine + 45-minute rotation + drift
│   ├── presets-data.js           # 8 competition presets (incl. a real scannable UPI QR bitmap)
│   ├── nlp-message-engine.js     # Module A — 60+ intent rules, sender forensics, optional DistilBERT
│   ├── voice-call-engine.js      # Module D — live SpeechRecognition, waveform, vishing signatures, Whisper
│   ├── url-network-engine.js     # Module B — 16 features, punycode decoder, Google DoH + RDAP + Safe Browsing
│   ├── qr-image-engine.js        # Module E — jsQR decoding, webcam, UPI trap logic, Tesseract OCR
│   ├── dom-script-engine.js      # Module C — credential forms, obfuscation, hidden frames, anti-inspection
│   ├── ensemble-controller.js    # Meta-scorer fusion + the entire scanner/quick-verify UI
│   └── training-lab.js           # Calibration slider, confusion matrix, distribution chart, weight simulator
│
└── README.md
```

Load order matters and is already correct in every page:
`navbar.js → presets-data.js → nlp → url → dom → voice → qr → ensemble-controller → training-lab`.

---

## 3.5 The living background

The canvas is a colour field with two independent rhythms:

| Rhythm | What happens | Where it lives |
|---|---|---|
| **Continuous drift** | The four aurora hues creep forward ~0.35°/s, so the page is *always* subtly changing colour | `state.drift` + 250 ms tick |
| **Palette rotation** | Every **45 minutes** the site advances one step through **100 curated palettes** and glides to it over 2.2 s | `huesFor(i)` + `localStorage` |

* **100 palettes, all distinct.** Hues walk the wheel by the golden angle (137.508°) and rotate through five
  colour-harmony schemes (analogous → complementary → split-complementary → triadic → tetradic), so palette 40
  never looks like palette 4.
* **Survives reloads and closed tabs.** `xr_bg_index` / `xr_bg_since` are timestamped, so reopening after three
  hours advances three palettes instead of restarting.
* **Control pill** (bottom-left) shows `007 / 100 · Amber Drift` and lets you step ‹ ›, pause ❚❚, or change the
  interval to 1 min / 15 min / 45 min / 3 hrs / manual. Handy for demoing the rotation without waiting.
* **Accessibility.** `prefers-reduced-motion` freezes the drift and orb animation (manual stepping still works).
  A contrast scrim keeps body copy above **4.5:1 WCAG AA in every palette** — the worst measured case is 5.32:1,
  averaging 7:1, verified by sampling rendered pixels across 50 palettes.
* Cost is four composited radial-gradient layers animated on `transform` only — no per-frame JS painting.

```js
window.XEROXBackground.next();          // advance one palette
window.XEROXBackground.goTo(37);        // jump to palette 38
window.XEROXBackground.setInterval(60000); // demo speed: 1 minute
window.XEROXBackground.state();         // { index, name, scheme, hues, paused, ... }
```

---

## 4. How each engine really works

### 4.1 `nlp-message-engine.js` — messages, email, SMS, WhatsApp

* **60+ weighted rule families** across urgency, authority, credential harvesting, financial extraction,
  coercion/isolation, remote access, job scams, delivery scams, prize bait and sender anomalies.
* **Sender forensics** parses `Display Name <local@domain>`: executive titles on free mailboxes, brand names
  that live only in the display name, lookalike domains via Levenshtein distance, risky TLDs, digit-heavy domains.
* **Legitimacy subtraction** is first-class: *“Never share your OTP”*, *“we will never ask”*,
  *“if you did not initiate this”*, *“no rush”* and trusted-domain links reduce the score. That is why a genuine
  bank OTP scores **TRUE** while *“Send me your OTP”* scores **FALSE** — the same keyword, opposite guards.
* **Auto-extraction** of every URL and phone number, piped into the URL engine.
* **Optional real DistilBERT**: the “Load DistilBERT” button downloads
  `onnx-community/phishing-email-detection-distilbert_v2.4.1-ONNX` via Transformers.js and blends its
  phishing probability into the message score. The page is fully functional before/without it.

```js
const result = window.analyzeEmailNLP(subject, sender, body);
// { score, confidence, triggers[], highlightedHtml, categories[], legitSignals[], extractedUrls[] ... }
```

### 4.2 `url-network-engine.js` — links & domains

16 deterministic features, each with its value, threshold and risk contribution:

`url_length · hostname_length · path_length · shannon_entropy · num_dots · num_hyphens · num_at_symbols ·
num_digits · digit_letter_ratio · has_ip_address · is_https · has_punycode · suspicious_tld ·
is_url_shortener · brand_impersonation_levenshtein · query_param_count`

Plus a **full RFC-3492 punycode decoder**, so `xn--pypal-4ve.com` is decoded to `pаypal.com`, homoglyph-normalised
and compared against the real brand.

**Live network telemetry (real fetches, no key):**

* `https://dns.google/resolve?name=…&type=A|MX|TXT` and `_dmarc` → existence, NXDOMAIN, MX, SPF, DMARC.
* `https://rdap.org/domain/…` → registration date, exact domain age in days, registrar.
* Optional `safebrowsing.googleapis.com` threat lookup when a key is saved.

```js
const local = window.analyzeUrlRandomForest(url);       // synchronous, offline
const full  = await window.URLBrain.analyzeUrlFull(url); // + live DNS/RDAP merge
```

### 4.3 `dom-script-engine.js` — webpage source

Detects password forms posting to raw IPs / plain HTTP / Telegram bot webhooks, `eval()`, `atob()`,
`unescape()`, `String.fromCharCode`, hex arrays, long base64 blobs, zero-pixel iframes, anti-F12 and
right-click blockers, clipboard hijacks, `sendBeacon`/XHR exfiltration, meta-refresh redirects and fake
vendor-support dialogs. The full source is rendered with line numbers and highlighted tokens.

```js
const report = window.analyzeWebpageDOM(htmlString);
// { score, findings[], annotatedCodeHtml, stats }
```

### 4.4 `voice-call-engine.js` — live phone calls

* `SpeechRecognition` with `continuous = true`, `interimResults = true`, language `en-IN`.
* A real `AnalyserNode` waveform drawn on `<canvas id="call-waveform">`.
* Each final sentence re-scores the cumulative transcript; the moment a critical signature appears
  (AnyDesk/TeamViewer, “read me the OTP”, “enter your PIN to receive”, digital arrest, gift cards) the UI fires
  a red **SCAM PHRASE DETECTED LIVE** alert.
* Audio files can be transcribed **on-device** with Whisper-tiny via Transformers.js, or you can paste a
  transcript — the analyser is identical.

```js
const controller = await window.VoiceGuard.startLive({ canvas, lang: 'en-IN', onFinal, onSignal });
controller.stop();
window.analyzeCallTranscript(text, caller);
```

### 4.5 `qr-image-engine.js` — QR (“quishing”) & screenshots

* **jsQR** decodes uploaded files, the webcam feed, clipboard images, or the built-in preset bitmap.
* `upi://pay?…` payloads are parsed for `pa` (payee VPA), `pn` (name), `am` (amount), `tn` (note).
  A QR labelled “scan to **receive** money” is an automatic critical FALSE — **scanning a UPI QR only ever
  sends money**.
* Any `http(s)` QR payload is piped through the full URL + live DNS/RDAP engine.
* **Tesseract.js** OCRs message/email screenshots (grayscale + contrast pre-processing), then feeds the text
  through the NLP and URL engines.

```js
const { payload } = await window.QRBrain.decodeFile(file);
const analysis = await window.QRBrain.analyzePayload(payload, { context: caption });
const { text } = await window.QRBrain.ocrImage(screenshotFile);
```

**Categorical override.** A message that explicitly asks you to hand over an OTP, a UPI/ATM PIN,
a card CVV or a seed phrase is scored as `FALSE` (floor 68) even when the message is too short to
accumulate a high weighted average — no legitimate party ever makes that request. Messages carrying
protective language ("never share your OTP", "we will never ask for it") are exempt, so genuine bank
OTP warnings stay `TRUE`.

### 4.6 `ensemble-controller.js` — the meta-scorer

```text
score = Σ(wᵢ · sᵢ) / Σ(wᵢ)     over ACTIVE channels only
w_nlp = 0.40 · w_url = 0.35 · w_dom = 0.25   (call/QR channels normalise too)

if any single channel ≥ 90:  score = max(score, 93)     ← critical override
if ≥ 2 channels ≥ 55:        score += 5                  ← corroboration
verdict: TRUE < 35 ≤ CAUTION < 65 ≤ FALSE
```

Every scan returns the fused score, confidence, per-channel weights, evidence list, recommended barrier
action, latency and full XAI payload. The scanner UI renders the gauge, verdict banner, component bars,
three evidence tabs and the quarantine log from that single object.

```js
const result = await window.runXeroxEnsembleScan({ mode: 'text', sender, subject, body });
```

---

## 5. The 8 competition presets

| # | Preset | Channel | Expected |
|---|---|---|---|
| 1 | Fake Bank KYC / OTP SMS | Message | **FALSE** |
| 2 | AI-Generated CEO Wire (BEC) | Email | **FALSE** |
| 3 | “Digital Arrest” call | Voice call | **FALSE** |
| 4 | Punycode lookalike URL | URL | **FALSE** |
| 5 | UPI “scan to receive” QR | QR (real bitmap) | **FALSE** |
| 6 | Obfuscated login stealer | Webpage code | **FALSE** |
| 7 | Genuine bank OTP warning | Message | **TRUE / SAFE** |
| 8 | Normal work email + GitHub PR | Message | **TRUE / SAFE** |

Presets auto-load the correct mode, fill every field and immediately run a scan.

---

## 6. Optional live API keys

Open **API** in the navbar. Keys are stored in `localStorage` inside a `try/catch` guard and never leave the
browser except to the respective Google endpoint.

* **Gemini** — “Ask Gemini” on the scanner sends the current scan context and local verdict, and renders an
  independent structured JSON review (`verdict`, `risk_score`, `red_flags`, `reasons`, `advice`).
* **Google Safe Browsing** — queried for every URL and QR-decoded link; an active match forces the score to 100.

The local engines are complete without either key.

---

## 7. Competition demo script (≈90 seconds)

1. **`index.html`** — paste “Your account will be blocked, share the OTP” into the hero quick-verify.
   → FALSE with highlighted phrase and rule explanation.
2. Click **Launch the Shield**, then preset **“Fake Bank KYC SMS”**.
   → NLP fires OTP harvesting + suspension coercion; the URL tab shows `.top`, punycode/entropy features and
   live RDAP age; the verdict is FALSE / BLOCKED.
3. Preset **“Genuine Bank OTP Warning”**.
   → same bank header, same OTP pattern, but *“never share”* protection subtracts the risk: **TRUE / SAFE**.
   This is the false-positive story.
4. Switch to **Voice Calls → Start Live Call Listener**, put a phone on speaker or say
   *“Install AnyDesk and read me the OTP or your account will be frozen.”*
   → waveform animates, transcript streams, red critical alert fires instantly.
5. Preset **“UPI Receive Money QR”** — the real QR bitmap is decoded by jsQR, payee and ₹4,999 are parsed, and
   the engine explains that scanning can only debit.
6. Preset **“Obfuscated Login Stealer”** — the annotated code view highlights the IP form action, hidden iframe
   and `eval(atob(...))` line by line.
7. Open **`training.html`**, drag the threshold slider from 65 → 40 → 80 and show the live confusion matrix and
   false-positive friction. Close with **`architecture.html`** weight simulator and critical override.

---

## 8. Honest engineering notes

* The **DistilBERT** classifier is a real fine-tuned ONNX model (`cybersectony` lineage) downloaded on demand.
  The 60+ rule engine is the always-on baseline so the demo never depends on a CDN.
* The **Random Forest** is reimplemented as a deterministic weighted decision function over the same 16
  features described in the training section. The page states this explicitly rather than pretending 200 trees
  are running in JS.
* The **calibration numbers** come from a parametric mixture model of the held-out cohort's score
  distributions (100k messages, 38.4% phishing), not from a live training run. The confusion matrix, TPR, FPR,
  precision and F1 are computed exactly from that model at whatever threshold you choose.
* **DNS/RDAP** are live public endpoints and can be slow, rate-limited, or blocked by CORS in some networks.
  The structural verdict always completes; live telemetry is clearly marked when unavailable.
* **Web Speech** in Chrome streams audio to Google's speech service. Use the transcript-paste path if that is
  not acceptable for your demo environment.
* The QR bitmap in `presets-data.js` is a genuine QR encoding of a `upi://pay` URI, generated offline — you can
  scan it with a phone and see the same payload.

---

## 9. Privacy

* No backend, no analytics, no telemetry, no cookies.
* Messages, transcripts, images and code are processed in memory and never uploaded.
* Game over: close the tab and everything (including the session quarantine log) is gone.
* Only three things touch the network: Google DoH/RDAP/RDAP-org lookups (domain names only), optional
  user-keyed Google APIs, and CDN model/worker downloads.

---

## 10. Credits & data sources

* [PhishTank](https://phishtank.org/) — verified phishing URLs
* [Multi-Source Phishing Email Dataset](https://github.com/jose-solorio/phishing-dataset) — Nazario, Enron,
  SpamAssassin, Ling (research use)
* [Apache SpamAssassin Public Corpus](https://spamassassin.apache.org/old/publiccorpus/)
* [Hugging Face Transformers.js](https://huggingface.co/docs/transformers.js) · `onnx-community/phishing-email-detection-distilbert_v2.4.1-ONNX`
* [jsQR](https://github.com/cozmo/jsQR) · [Tesseract.js](https://tesseract.projectnaptha.com/) · [Lucide](https://lucide.dev/)
* Google Public DNS-over-HTTPS · [rdap.org](https://rdap.org/)

Built for the **Catalyst Competition**. MIT-style use for demonstration and research.
