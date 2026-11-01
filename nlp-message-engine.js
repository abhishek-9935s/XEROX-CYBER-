/* ============================================================
   XEROX — nlp-message-engine.js  (Module A)
   Real semantic-intent engine for Email / SMS / WhatsApp / chat.

   1. 60+ weighted manipulation-pattern families (deterministic,
      zero-latency, works with no network).
   2. Sender / display-name / domain forensics.
   3. Auto URL + phone extraction piped to url-network-engine.js.
   4. Legitimate-context recognition to prevent false positives
      ("Never share your OTP" is SAFE; "Send me your OTP" is SCAM).
   5. Optional real DistilBERT neural layer loaded lazily through
      Hugging Face Transformers.js (ONNX quantised weights).
   ============================================================ */
(function () {
  'use strict';

  const NEURAL_MODEL_ID = 'onnx-community/phishing-email-detection-distilbert_v2.4.1-ONNX';
  const TRANSFORMERS_CDN = 'https://cdn.jsdelivr.net/npm/@huggingface/transformers@3.0.0';

  /* ----------------------------------------------------------
     0. Small local helpers (self-contained module)
     ---------------------------------------------------------- */
  const SUSPICIOUS_TLDS = ['xyz', 'top', 'click', 'zip', 'tk', 'buzz', 'loan', 'work', 'gq', 'ml', 'cf', 'country', 'stream', 'download', 'racing', 'win', 'bid', 'date', 'faith', 'review', 'party', 'cricket', 'science', 'accountant'];
  const SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'rb.gy', 'is.gd', 'cutt.ly', 'shorturl.at', 'tiny.cc', 'ow.ly', 'buff.ly'];
  const TRUSTED_DOMAINS = ['github.com', 'gitlab.com', 'stripe.com', 'google.com', 'google.co.in', 'microsoft.com', 'apple.com', 'amazon.com', 'amazon.in', 'hdfcbank.com', 'icicibank.com', 'sbi.co.in', 'onlinesbi.sbi', 'axisbank.com', 'kotak.com', 'paypal.com', 'linkedin.com', 'zoom.us', 'slack.com', 'notion.so', 'npmjs.com', 'mozilla.org', 'wikipedia.org', 'cloudflare.com', 'vercel.com', 'supabase.com', 'gov.in', 'nic.in', 'irctc.co.in', 'uidai.gov.in'];
  const FREE_MAIL = ['gmail.com', 'yahoo.com', 'yahoo.co.in', 'outlook.com', 'hotmail.com', 'live.com', 'protonmail.com', 'proton.me', 'aol.com', 'mail.ru', 'gmx.com', 'zoho.com', 'yandex.com'];
  const BRANDS = ['paypal', 'microsoft', 'google', 'apple', 'amazon', 'netflix', 'facebook', 'instagram', 'whatsapp', 'hdfc', 'icici', 'sbi', 'axis', 'kotak', 'flipkart', 'myntra', 'swiggy', 'zomato', 'irctc', 'binance', 'coinbase', 'metamask', 'stripe', 'linkedin', 'dropbox', 'adobe', 'dhl', 'fedex', 'usps', 'royalmail', 'indiapost'];

  const esc = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');

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

  const HOMOGLYPHS = { 'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ї': 'i', 'ѕ': 's', 'ԁ': 'd', 'ɡ': 'g', 'ӏ': 'l', 'ο': 'o', 'α': 'a', 'ν': 'v', 'ι': 'i', 'κ': 'k', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'η': 'n', 'о': 'o', 'ａ': 'a', 'ｅ': 'e', 'ⅼ': 'l', 'ⅰ': 'i', '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a' };
  function normalizeHomoglyphs(s) {
    return String(s).toLowerCase().split('').map(ch => HOMOGLYPHS[ch] || ch).join('');
  }

  function hostOf(urlStr) {
    try {
      const u = new URL(urlStr.startsWith('http') ? urlStr : 'http://' + urlStr);
      return u.hostname.toLowerCase().replace(/^www\./, '');
    } catch (e) { return ''; }
  }
  function tldOf(host) {
    const parts = String(host).split('.');
    return parts.length > 1 ? parts[parts.length - 1] : '';
  }
  function isTrustedHost(host) {
    return TRUSTED_DOMAINS.some(d => host === d || host.endsWith('.' + d));
  }

  /* ----------------------------------------------------------
     1. Rule families
     Each rule: id, category, weight (0-10), label, detail,
     re (RegExp), optional guard(text, index, match).
     ---------------------------------------------------------- */

  /* Guard: don't fire a "request" rule when the phrase is protective
     (never share / do not disclose / we will never ask). */
  function notProtective(text, index) {
    const before = text.slice(Math.max(0, index - 26), index).toLowerCase();
    return !/(never|do not|don't|dont|not to|shouldn't|should not|will never|won't)\s+(ever\s+)?$/.test(before) &&
           !/(never|do not|don't|dont|not to|shouldn't|should not|will never|won't)\s+(share|send|give|tell|provide|disclose|forward|read)\s+(your\s+|the\s+|me\s+|us\s+)?$/i.test(before);
  }

  const RULES = [
    /* ---------------- Coercive urgency & time pressure ---------------- */
    { id: 'u-immediately', category: 'urgency', weight: 4, label: 'Artificial urgency', detail: 'Pressure language ("immediately", "right away") compresses the victim\'s decision window.', re: /\b(immediately|right away|at once|without (?:any )?delay|on an urgent basis)\b/gi },
    { id: 'u-window', category: 'urgency', weight: 5, label: 'Countdown deadline', detail: 'A very short numeric window ("within 10 minutes") is a hallmark of coercive phishing.', re: /\b(within|in the next)\s+\d{1,2}\s*(minutes?|mins?|hours?|hrs?)\b/gi },
    { id: 'u-expire', category: 'urgency', weight: 2, label: 'Expiry pressure', detail: 'Short validity wording. Legitimate when paired with "never share"; suspicious when paired with a request.', re: /\b(expires?|expiring|valid (?:only )?for)\s+(?:in\s+|next\s+)?\d{1,2}\s*(?:min|mins|minutes?|hours?|hrs?)\b/gi },
    { id: 'u-before-deadline', category: 'urgency', weight: 2, label: 'Same-day deadline', detail: 'A same-day cut-off ("before 3:00 PM today") is used to short-circuit verification.', re: /\bbefore\s+\d{1,2}(?::\d{2})?\s*(?:am|pm|a\.m\.|p\.m\.)\b/gi },
    { id: 'u-final-warning', category: 'urgency', weight: 5, label: 'Final-warning framing', detail: '"Final notice / last chance / act now" escalates fear to force a click.', re: /\b(final (?:warning|notice|reminder)|last chance|act now|urgent action (?:required|needed)|immediate action)\b/gi },
    { id: 'u-account-blocked', category: 'urgency', weight: 7, label: 'Account-block threat', detail: 'Threatening that an account "will be blocked/suspended" is the most common smishing hook in India.', re: /\b(account|profile|card|service|sim|number)\b[^.!?\n]{0,45}\b(will be (?:blocked|suspended|frozen|deactivated|closed|disconnected)|has been (?:blocked|suspended|limited|restricted))\b/gi },
    { id: 'u-avoid-suspension', category: 'urgency', weight: 6, label: 'Suspension penalty', detail: 'Promising "permanent suspension or penalties" if the recipient does not act.', re: /\b(avoid|prevent)\b[^.!?\n]{0,32}\b(permanent )?(suspension|block(?:ing|age)?|termination|deactivation|penalt(?:y|ies)|legal action)\b/gi },
    { id: 'u-timeout-threat', category: 'urgency', weight: 7, label: 'Timed freeze threat', detail: 'A freeze/block tied to a literal countdown ("frozen in 10 minutes") is coercive and never used by real banks.', re: /\b(frozen|blocked|closed|terminated|deactivated)\s+(?:in|within)\s+\d{1,2}\s*(minutes?|mins?|hours?)\b/gi },

    /* ---------------- Authority & impersonation ---------------- */
    { id: 'a-gov-agency', category: 'authority', weight: 5, label: 'Agency / regulator name-drop', detail: 'CBI, Customs, TRAI, RBI, Police or "Cyber Crime Cell" used to borrow authority.', re: /\b(cbi|fbi|cia|income tax(?: department)?|enforcement directorate|ed officer|customs(?: department)?|narcotics(?: control)?|police(?: department| commissioner)?|cyber crime(?: cell| branch)?|supreme court|high court|trai|rbi|sebi)\b/gi },
    { id: 'a-case-registered', category: 'authority', weight: 7, label: 'Fake legal case', detail: 'Claims that an FIR/warrant/case exists are a core "digital arrest" intimidation script.', re: /\b(case (?:has been |is )?(?:registered|filed|made)|fir\b|non[- ]bailable warrant|arrest warrant|court (?:notice|summons)|legal (?:case|notice|proceedings))\b/gi },
    { id: 'a-exec-title', category: 'authority', weight: 4, label: 'Executive authority', detail: 'CEO/CFO/Director framing is used in business email compromise to demand secrecy and speed.', re: /\b(ceo|cfo|coo|cto|chairman|managing director|chief executive|founder|hr head|it admin(?:istrator)?|accounts head)\b/gi },
    { id: 'a-confidential-task', category: 'authority', weight: 5, label: 'Confidentiality demand', detail: '"Strictly confidential" tasks are used to stop employees from checking with colleagues.', re: /\b(strictly confidential|top secret|confidential (?:task|matter|request|assignment)|do not discuss|keep this confidential|between us)\b/gi },
    { id: 'a-bypass-process', category: 'authority', weight: 6, label: 'Approval bypass', detail: 'Asking to skip the normal approval chain removes the exact control that stops wire fraud.', re: /\b(bypass|skip|outside)\s+(?:the\s+)?(?:usual\s+|normal\s+|standard\s+)?(?:approval|process|chain|policy)\b|\b(cannot|can't|don't) wait (?:for|on) the (?:usual|normal|standard)?\s*(?:approval|process|chain)\b/gi },
    { id: 'a-alt-inbox', category: 'authority', weight: 6, label: 'Alternate inbox redirect', detail: 'Asking to reply to a "personal / alternate inbox" moves the conversation away from corporate mail controls.', re: /\b(alternate|personal|private|new|backup) (?:inbox|email(?: address)?|id|address)\b/gi },
    { id: 'a-it-excuse', category: 'authority', weight: 5, label: 'IT-outage excuse', detail: '"Email sync issues / server down" explains away why the executive is using a different domain.', re: /\b(sync(?:ing)? issues?|email (?:is )?(?:down|not working)|having trouble (?:accessing|receiving)|server (?:is )?down|mailbox is full)\b/gi },
    { id: 'a-gov-fee', category: 'authority', weight: 4, label: 'Official-sounding desk', detail: 'Fake "government treasury / verification officer / cyber desk" constructs create legitimacy.', re: /\b(government|govt|treasury|verification|compliance|security) (?:account|department|officer|desk|portal|team)\b/gi },

    /* ---------------- Credential & identity harvesting ---------------- */
    { id: 'c-otp-request', category: 'credentials', weight: 10, label: 'OTP request', detail: 'No bank, app or government officer ever needs your OTP. Any request to share/read it is account takeover.', re: /\b(share|send|provide|give|tell|forward|read(?:\s+(?:me|out|aloud))?|disclose|confirm)\b[^.!?\n]{0,45}\b(otp|o\.t\.p\.?|one[- ]time (?:password|code)|6[- ]digit (?:code|otp|pin)|verification code|security code)\b/gi, guard: notProtective },
    { id: 'c-pin-request', category: 'credentials', weight: 9, label: 'PIN / UPI PIN request', detail: 'A UPI PIN authorises a debit. It is never required to "receive" money or "cancel" a request.', re: /\b(share|send|provide|give|tell|read|enter|type|approve)\b[^.!?\n]{0,40}\b(upi\s?pin|atm pin|debit card pin|profile pin|m[- ]?pin)\b/gi, guard: notProtective },
    { id: 'c-password-reset', category: 'credentials', weight: 6, label: 'Credential re-entry', detail: 'Pushing the user to re-enter or "confirm" a password is the final step of most credential harvesters.', re: /\b(reset|re-?enter|update|confirm|verify|validate)\b[^.!?\n]{0,28}\b(password|passcode|credentials?|login details|username)\b/gi },
    { id: 'c-mfa', category: 'credentials', weight: 4, label: '2FA / authenticator mention', detail: 'MFA codes are a favourite target for real-time adversary-in-the-middle phishing.', re: /\b(2fa|two[- ]factor|mfa|authenticator (?:code|app)|authenticator number)\b/gi },
    { id: 'c-card-details', category: 'credentials', weight: 8, label: 'Card data request', detail: 'CVV / full card numbers are never collected through an unsolicited message or call.', re: /\b(cvv|cvc|card number|16[- ]digit|expiry date|debit card details|credit card details|card details|payment details|billing details|card (?:and )?pin)\b|\b(re-?enter|confirm|update|verify)\b[^.!?\n]{0,28}\b(card|payment|billing)\b/gi },
    { id: 'c-seed-phrase', category: 'credentials', weight: 10, label: 'Wallet seed phrase', detail: 'A seed phrase gives total control of a crypto wallet. Any request is a guaranteed theft attempt.', re: /\b(seed phrase|recovery phrase|private key|mnemonic|wallet (?:phrase|key|restore))\b/gi },
    { id: 'c-kyc-docs', category: 'credentials', weight: 6, label: 'KYC data harvesting', detail: 'KYC "completion" requests are used to harvest Aadhaar/PAN identity documents.', re: /\b(complete|update|re-?verify|finish)\b[^.!?\n]{0,24}\bkyc\b|\bkyc\b[^.!?\n]{0,24}\b(pending|incomplete|expired|failed|suspended)\b|\b(aadhaar|aadhar|pan card)\b[^.!?\n]{0,30}\b(photo|copy|number|details|verification|update)\b/gi },

    /* ---------------- Financial extraction ---------------- */
    { id: 'f-wire', category: 'financial', weight: 7, label: 'Transfer instruction', detail: 'Direct instructions to wire/transfer money are the payload of business email compromise.', re: /\b(wire transfer|bank transfer|transfer (?:the )?(?:funds|amount|money)|remit|swift transfer|neft|rtgs|imps|send (?:the )?money|make the payment)\b/gi },
    { id: 'f-amount', category: 'financial', weight: 5, label: 'Specific money amount', detail: 'A precise amount accelerates the victim into a single, unrecoverable transaction.', re: /(?:₹|rs\.?|inr|usd|\$|£|€)\s?[\d,]{2,}(?:\.\d{1,2})?(?:\s?(?:lakh|crore|k|million|thousand))?/gi },
    { id: 'f-beneficiary', category: 'financial', weight: 5, label: 'Beneficiary details', detail: 'Account number / IFSC / UPI ID collection is only needed when money is about to leave.', re: /\b(beneficiary|account (?:number|details|no)|ifsc|sort code|routing number|upi id|vpa|payee)\b/gi },
    { id: 'f-prize', category: 'financial', weight: 7, label: 'Prize / lottery bait', detail: 'Unsolicited winnings are always followed by a "processing fee" or data request.', re: /\b(you (?:have )?won|you are (?:a )?winner|congratulations[!,. ]+you|lucky (?:draw|winner)|prize money|lottery (?:winner|draw)|jackpot)\b/gi },
    { id: 'f-refund', category: 'financial', weight: 5, label: 'Refund lure', detail: 'Fake refunds ("scan to receive") are the most common UPI fraud in India.', re: /\b(refund|reimbursement|cashback)\b[^.!?\n]{0,45}\b(process|claim|receive|pending|credited|scan|share|link)\b/gi },
    { id: 'f-tax', category: 'financial', weight: 6, label: 'Tax-refund bait', detail: 'Income-tax refund messages peak every filing season and always lead to a credential form.', re: /\b(tax refund|income[- ]tax refund|tds refund|gst refund|it refund)\b/gi },
    { id: 'f-loan', category: 'financial', weight: 5, label: 'Loan / credit bait', detail: 'Pre-approved loan offers from unknown senders often precede advance-fee or data-harvesting traps.', re: /\b(pre[- ]?approved|instant|guaranteed) (?:loan|credit|limit)|loan (?:approved|disbursed)\b/gi },
    { id: 'f-gift-card', category: 'financial', weight: 8, label: 'Gift-card payment', detail: 'Gift cards are untraceable — no legitimate employer or agency requests them as payment.', re: /\b(gift cards?|itunes card|google play card|amazon card|steam card)\b/gi },
    { id: 'f-crypto', category: 'financial', weight: 5, label: 'Crypto payment rail', detail: 'Crypto transfers are irreversible and heavily used by investment and romance scammers.', re: /\b(bitcoin|usdt|trc20|erc20|crypto wallet|binance|metamask|tether)\b/gi },
    { id: 'f-advance-fee', category: 'financial', weight: 8, label: 'Advance-fee demand', detail: 'Paying a "small fee" to unlock a prize/loan/refund is the definition of advance-fee fraud.', re: /\b(pay (?:a )?(?:small|nominal|refundable) (?:fee|amount|charge|deposit)|(?:registration|joining|security|processing|clearance|customs|handling|activation) (?:fee|charge|deposit|tax))\b/gi },

    /* ---------------- Threats, isolation & coercion ---------------- */
    { id: 'co-do-not-tell', category: 'coercion', weight: 9, label: 'Isolation instruction', detail: '"Do not tell your family or bank" exists only to stop the victim from getting a second opinion.', re: /\b(do not|don'?t|never) (?:tell|inform|involve|contact|alert)\s+(?:anyone|anybody|your (?:family|parents|husband|wife|friends?|colleagues?|bank|lawyer))\b/gi },
    { id: 'co-do-not-disconnect', category: 'coercion', weight: 8, label: 'Call-control demand', detail: 'Keeping a victim on the line ("do not disconnect") prevents verification with the real institution.', re: /\b(do not|don'?t) (?:disconnect|hang up|end (?:this )?call|cut (?:the|this) call|drop the call)\b/gi },
    { id: 'co-secrecy', category: 'coercion', weight: 8, label: 'Secrecy demand', detail: 'Instructions to keep the interaction secret are a reliable abuse signal.', re: /\b(keep (?:this|it) (?:secret|confidential|between us|quiet)|no one (?:must|should) know|off the (?:record|group|thread)|out of the (?:group|thread))\b/gi },
    { id: 'co-legal-threat', category: 'coercion', weight: 6, label: 'Legal threat', detail: 'Threats of arrest or prosecution are used to replace rational verification with fear.', re: /\b(legal action|prosecut(?:e|ion)|lawsuit|place (?:you )?under arrest|jail|imprisonment|penalty of|non[- ]bailable)\b/gi },
    { id: 'co-digit-code', category: 'coercion', weight: 5, label: 'Verification code coercion', detail: 'Reading a freshly received code aloud hands over a live session or transaction.', re: /\b(read|say|speak|tell (?:me|us)|dictate)\b[^.!?\n]{0,30}\b(?:code|otp|number|digits?)\b[^.!?\n]{0,20}\b(?:aloud|out loud|now|immediately)\b/gi },
    { id: 'co-video-call', category: 'coercion', weight: 6, label: 'Forced video interrogation', detail: '"Digital arrest" scripts force a Skype/Zoom video call to simulate an official interrogation.', re: /\b(skype|zoom|video call|video conference)\b[^.!?\n]{0,60}\b(registrar|officer|verification|interrogat|case|arrest|investigation)\b/gi },

    /* ---------------- Remote access (critical) ---------------- */
    { id: 'r-remote-app', category: 'remote', weight: 10, label: 'Remote-access software', detail: 'AnyDesk / TeamViewer / RustDesk give a stranger full control of the device and banking apps.', re: /\b(anydesk|teamviewer|rustdesk|quick ?support|ultraviewer|ammyy|logmein|splashtop|screen (?:sharing|mirroring)|mirror your screen)\b/gi },
    { id: 'r-apk', category: 'remote', weight: 9, label: 'APK sideload demand', detail: 'Sideloaded .apk files can read SMS/OTP and overlay fake banking screens.', re: /\b(install|download|sideload)\b[^.!?\n]{0,32}\b(apk|\.apk file|unknown app|remote (?:access|support) app|any\s?desk)\b/gi },
    { id: 'r-screen-share', category: 'remote', weight: 7, label: 'Screen-sharing request', detail: 'Screen sharing exposes OTPs and account balances in real time.', re: /\b(share your screen|screen share|allow (?:me |us )?remote access|grant access to your (?:phone|device|screen))\b/gi },

    /* ---------------- Job, task & delivery scams ---------------- */
    { id: 'j-work-home', category: 'job', weight: 7, label: 'Work-from-home bait', detail: 'Part-time / daily-payout job spam is the top WhatsApp and Telegram scam category in India.', re: /\b(work from home|part[- ]time job|earn (?:₹|rs\.?|inr|\$)?\s?[\d,]+ ?(?:per day|daily|weekly)|daily payout|simple typing job|youtube like (?:job|task)|telegram (?:task|group|job))\b/gi },
    { id: 'j-registration-fee', category: 'job', weight: 8, label: 'Job prepayment', detail: 'No real employer charges a registration or security deposit before hiring.', re: /\b(registration|joining|security|training|kit) (?:fee|deposit|charge|amount)\b/gi },
    { id: 'd-delivery', category: 'delivery', weight: 6, label: 'Parcel-hold lure', detail: 'Fake courier "customs hold / failed delivery" messages lead to a fee or OTP form.', re: /\b(parcel|package|shipment|courier)\b[^.!?\n]{0,50}\b(customs|detained|held|unpaid|failed (?:delivery|attempt)|reschedule|address issue|return to sender)\b/gi },
    { id: 'd-carrier', category: 'delivery', weight: 3, label: 'Courier brand name', detail: 'Courier brand names are frequently spoofed in smishing. Legitimate tracking links live on the carrier\'s own domain.', re: /\b(india ?post|speed post|dtdc|bluedart|delhivery|fedex|dhl|usps|royal mail|dpd)\b/gi },
    { id: 'p-prize-claim', category: 'prize', weight: 5, label: 'Claim-your-reward CTA', detail: '"Claim your reward" invites a click into a data-harvesting flow.', re: /\b(claim|redeem)\b[^.!?\n]{0,25}\b(prize|reward|voucher|gift|cashback|points)\b/gi },
    { id: 'p-selected', category: 'prize', weight: 5, label: 'Selected-winner framing', detail: 'Mass "you have been selected" framing is a classic mass-phishing opener.', re: /\b(you have been selected|you are selected|congratulations[!,. ]+you have|specially selected)\b/gi },

    /* ---------------- Social-engineering context ---------------- */
    { id: 'm-telegram-whatsapp', category: 'context', weight: 4, label: 'Off-platform migration', detail: 'Pushing the conversation to WhatsApp/Telegram evades corporate and banking monitoring.', re: /\b(telegram|whatsapp)\b[^.!?\n]{0,45}\b(click|join|contact|message|dm|chat|group)\b/gi },
    { id: 'm-short-url', category: 'link', weight: 6, label: 'Shortened link', detail: 'Shorteners hide the real destination and are heavily used to bypass link filters.', re: /\b(bit\.ly|tinyurl\.com|t\.co|rb\.gy|is\.gd|cutt\.ly|shorturl\.at|tiny\.cc|ow\.ly)\b/gi },
    { id: 'm-generic-greeting', category: 'context', weight: 2, label: 'Generic salutation', detail: '"Dear Customer" instead of your name indicates a mass send. On its own this is weak evidence.', re: /^\s*(dear (?:customer|user|client|member|sir\s*\/\s*madam|candidate|beneficiary)|valued customer|attention (?:user|customer))\b/gim },
    { id: 'm-verify-identity', category: 'context', weight: 6, label: 'Identity re-verification', detail: '"Verify your identity/account" is the standard wrapper around a credential form.', re: /\b(verify your (?:identity|account|details|information)|confirm your (?:identity|account|details)|re[- ]?verify your account)\b/gi },
    { id: 'm-unusual-activity', category: 'context', weight: 5, label: 'Unusual-activity hook', detail: 'Fabricated "suspicious login" alerts create alarm that the attacker then resolves.', re: /\b(unusual|suspicious|unauthori[sz]ed)\b[^.!?\n]{0,35}\b(activity|login|transaction|access|attempt|device)\b/gi },
    { id: 'm-click-here', category: 'context', weight: 4, label: 'Generic click CTA', detail: '"Click here" hides the destination from the reader.', re: /\b(click|tap|follow)\s+(?:here|this link|the link|below)\b/gi },
    { id: 'm-offer', category: 'context', weight: 4, label: 'Unsolicited offer', detail: 'Unsolicited high-value offers are a standard lure across every channel.', re: /\b(exclusive (?:offer|deal)|limited[- ]time (?:offer|deal)|free gift|100% free|no cost)\b/gi },
    { id: 'm-otp-numeric', category: 'context', weight: 0, label: 'OTP-shaped code present', detail: 'A 4–8 digit code was found. Used only to contextualise, never to score on its own.', re: /\b\d{4,8}\b/g },
    { id: 'm-phone-callback', category: 'context', weight: 3, label: 'Callback pressure', detail: 'A phone number pushed as the only resolution channel is common in vishing follow-ups.', re: /\b(call (?:us|me) (?:back )?(?:immediately|now|at)|call this number|helpline number)\b/gi },

    /* ---------------- Sender-level (applied on header) ---------------- */
    { id: 's-exec-free-mail', category: 'sender', weight: 7, label: 'Executive on free mail', detail: 'A "CEO/HR/Director" writing from Gmail/Yahoo/Outlook instead of the corporate domain is a BEC red flag.', re: /(?!)/g, applied: 'sender' },
    { id: 's-suspicious-sender-tld', category: 'sender', weight: 7, label: 'Sender domain on a risky TLD', detail: 'Cheap throw-away TLDs host the majority of freshly registered phishing domains.', re: /(?!)/g, applied: 'sender' },
    { id: 's-display-mismatch', category: 'sender', weight: 9, label: 'Display-name / domain mismatch', detail: 'The display name claims a brand or person that the actual sending domain does not own.', re: /(?!)/g, applied: 'sender' },
    { id: 's-reply-mismatch', category: 'sender', weight: 6, label: 'Reply-to divergence', detail: 'Replies are being funnelled to a different domain than the sender claims.', re: /(?!)/g, applied: 'sender' },
    { id: 's-lookalike-sender', category: 'sender', weight: 9, label: 'Lookalike sender domain', detail: 'The domain is a typo/homoglyph variant of a well-known brand.', re: /(?!)/g, applied: 'sender' },
    { id: 's-numeric-sender', category: 'sender', weight: 3, label: 'Digit-heavy sender domain', detail: 'Long digit runs in a domain correlate with auto-generated phishing infrastructure.', re: /(?!)/g, applied: 'sender' }
  ];

  /* ----------------------------------------------------------
     2. Legitimate-context recognisers (false-positive guards)
     ---------------------------------------------------------- */
  const LEGIT_SIGNALS = [
    { id: 'lg-never-share', weight: 16, label: 'Explicit "never share" safety notice', detail: 'Genuine banks warn you NOT to share the code. This cancels an OTP-request reading.', re: /\b(never|do not|don'?t|shouldn'?t)\s+(?:ever\s+)?(?:share|disclose|give|forward|reveal)\b[^.!?\n]{0,45}\b(otp|o\.t\.p\.?|pin|password|code|details)\b/gi },
    { id: 'lg-never-ask', weight: 10, label: 'Institution declares it never asks', detail: 'The message states the institution will never request credentials — a strong legitimacy marker.', re: /\b(?:we|the (?:bank|company)|bank|company)\s+(?:will\s+)?never\s+(?:ask|request|call|contact)\b[^.!?\n]{0,50}\b(otp|pin|password|details|credentials)\b/gi },
    { id: 'lg-not-initiated', weight: 8, label: 'Fraud-report path offered', detail: 'Genuine alerts tell you what to do if you did NOT initiate the action.', re: /\bif you (?:did not|didn'?t|have not|haven'?t) (?:initiate|request|authori[sz]e|make this)\b/gi },
    { id: 'lg-no-rush', weight: 7, label: 'Explicitly non-urgent', detail: '"No rush / at your convenience" is the opposite of coercion.', re: /\b(no rush|no hurry|at your convenience|whenever you get a chance|not urgent|take your time|if you are busy)\b/gi },
    { id: 'lg-do-not-forward', weight: 4, label: 'Do-not-forward instruction', detail: 'A protective instruction that reduces risk rather than creating it.', re: /\bdo not forward (?:this )?(?:message|email|code)\b/gi },
    { id: 'lg-thanks', weight: 3, label: 'Collaborative close', detail: 'Casual thanks/closing tone is typical of genuine colleague mail.', re: /\b(thanks|thank you|cheers|appreciate it)\b[.!]?\s*$/gim },
    { id: 'lg-otp-context', weight: 5, label: 'OTP described as outbound', detail: 'The code is presented as something the recipient requested, not something to hand over.', re: /\b(\d{4,8})\s+is your\b[^.!?\n]{0,40}\b(otp|one[- ]time password|verification code)\b/gi },
    { id: 'lg-receipt', weight: 4, label: 'Receipt-style language', detail: 'Standard transactional receipt language matches normal billing mail.', re: /\b(receipt|invoice (?:paid|#)|payment (?:received|successful)|your (?:order|subscription) (?:has been|is) (?:confirmed|shipped|renewed))\b/gi }
  ];

  /* ----------------------------------------------------------
     3. Extraction helpers
     ---------------------------------------------------------- */
  function extractUrls(text) {
    const out = [];
    if (!text) return out;
    const re = /((?:https?:\/\/|www\.)[^\s<>"'`)\]]+)/gi;
    let m;
    while ((m = re.exec(text)) !== null) {
      let raw = m[0].replace(/[.,;:]+$/, '');
      let normalized = raw.startsWith('www.') ? 'https://' + raw : raw;
      out.push({ raw, url: normalized, start: m.index, end: m.index + raw.length, host: hostOf(normalized) });
    }
    /* Bare domains without a scheme (skip anything that is part of an email) */
    const bare = /\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|in|io|co|xyz|top|click|info|biz|online|site|club|live|shop|store|app|dev|me|tk|buzz|loan|work|link|pro|ru|cn|uk|us|ca|de|au|fr|jp|sg|ae|sa|pk|bd|lk|np))\b(?:\/[^\s<>"')]*)?/gi;
    while ((m = bare.exec(text)) !== null) {
      const before = text.slice(Math.max(0, m.index - 1), m.index);
      if (before === '@' || before === '.') continue;
      if (out.some(u => m.index >= u.start - 2 && m.index <= u.end + 2)) continue;
      const raw = m[0].replace(/[.,;:]+$/, '');
      out.push({ raw, url: 'https://' + raw, start: m.index, end: m.index + raw.length, host: hostOf('https://' + raw) });
    }
    return out.sort((a, b) => a.start - b.start);
  }

  function extractPhones(text) {
    if (!text) return [];
    const out = new Set();
    const patterns = [
      /\b(?:\+91[\s-]?)?[6-9]\d{9}\b/g,
      /\b1800[\s-]?\d{3}[\s-]?\d{3,4}\b/g,
      /\+\d{1,3}[\s-]\d{6,14}\b/g
    ];
    patterns.forEach(re => { let m; while ((m = re.exec(text)) !== null) out.add(m[0].trim()); });
    return Array.from(out);
  }

  /* ----------------------------------------------------------
     4. Sender forensics
     ---------------------------------------------------------- */
  function analyzeSender(senderRaw) {
    const signals = [];
    if (!senderRaw || !String(senderRaw).trim()) {
      return { address: '', display: '', domain: '', signals, hasAddress: false };
    }
    const raw = String(senderRaw).trim();
    const angle = raw.match(/<([^>]+)>/);
    const address = (angle ? angle[1] : (raw.match(/[\w.+-]+@[\w.-]+\.\w+/) || [''])[0]).trim().toLowerCase();
    const at = address.lastIndexOf('@');
    const domain = at > -1 ? address.slice(at + 1) : '';
    const display = angle ? raw.slice(0, raw.indexOf('<')).trim().replace(/^["']|["']$/g, '') : (at > -1 ? '' : raw);

    if (!domain) {
      signals.push({ id: 's-no-domain', label: 'No valid sender address', detail: 'The sender is a bare SMS header or name with no verifiable domain.', weight: 2 });
      return { address, display, domain, signals, hasAddress: false };
    }

    const local = address.slice(0, at);
    const tld = domain.split('.').pop();
    const displayLower = display.toLowerCase();
    const execWords = /(ceo|cfo|coo|cto|chairman|managing director|director|founder|hr head|it admin|accounts|manager|officer|police|cbi|customs|bank|support|security team|helpdesk)/i;

    /* Executive / authority display from a free mailbox */
    if (execWords.test(displayLower + ' ' + local) && FREE_MAIL.includes(domain)) {
      signals.push({ id: 's-exec-free-mail', label: 'Authority identity on free mail', detail: `"${display || local}" writes from ${domain} — a consumer mailbox cannot represent a company or agency.`, weight: 7 });
    }

    /* Suspicious TLD */
    if (SUSPICIOUS_TLDS.includes(tld)) {
      signals.push({ id: 's-suspicious-sender-tld', label: 'Risky sender TLD', detail: `The sender domain ends in .${tld}, a cheap TLD disproportionately used for phishing.`, weight: 7 });
    }

    /* Display name claims a brand the domain does not own */
    const displayBrand = BRANDS.find(b => displayLower.includes(b));
    const localBrand = BRANDS.find(b => normalizeHomoglyphs(local).includes(b));
    if (displayBrand && !(domain === displayBrand + '.com' || domain.endsWith('.' + displayBrand + '.com') || domain.includes(displayBrand))) {
      signals.push({ id: 's-display-mismatch', label: 'Brand name in display only', detail: `Display name claims ${displayBrand}, but the envelope domain is ${domain}.`, weight: 9 });
    } else if (localBrand && !domain.includes(localBrand)) {
      signals.push({ id: 's-display-mismatch', label: 'Brand in local-part only', detail: `The mailbox local-part contains "${localBrand}" but the domain is ${domain}.`, weight: 6 });
    }

    /* Lookalike domain (typosquat / homoglyph) */
    const flat = normalizeHomoglyphs(domain.replace(/\.[a-z]+$/, '').replace(/[^a-z0-9]/g, ''));
    for (const brand of BRANDS) {
      if (brand.length < 5) continue;
      if (domain.includes(brand)) continue;
      const dist = levenshtein(flat, brand);
      if (dist > 0 && dist <= 2) {
        signals.push({ id: 's-lookalike-sender', label: 'Lookalike sender domain', detail: `${domain} is ${dist} edit(s) away from ${brand}.com — a classic typosquat.`, weight: 9 });
        break;
      }
    }

    /* Digit-heavy domain */
    if ((domain.match(/\d/g) || []).length >= 3) {
      signals.push({ id: 's-numeric-sender', label: 'Digit-heavy domain', detail: 'Multiple digits in a domain frequently indicate auto-generated phishing infrastructure.', weight: 3 });
    }

    /* Reply-to divergence written in the body is handled by a textual rule */
    return { address, display, domain, signals, hasAddress: true };
  }

  /* ----------------------------------------------------------
     5. Rule scanning
     ---------------------------------------------------------- */
  function scanRules(text, rules, collectPositions) {
    const hits = [];
    for (const rule of rules) {
      if (rule.applied === 'sender') continue;
      const flags = rule.re.flags.includes('g') ? rule.re.flags : rule.re.flags + 'g';
      const re = new RegExp(rule.re.source, flags);
      let m, count = 0;
      while ((m = re.exec(text)) !== null) {
        if (m[0].length === 0) { re.lastIndex++; continue; }
        if (rule.guard && !rule.guard(text, m.index, m[0])) continue;
        if (!collectPositions && count >= 1) break;
        if (count >= 2) break;
        hits.push({ rule, text: m[0], start: m.index, end: m.index + m[0].length, occurrence: count });
        count++;
      }
    }
    return hits;
  }

  /* Build highlighted HTML with tooltips, resolving overlaps by weight */
  function buildHighlights(text, hits) {
    if (!text) return '';
    const marks = hits.filter(h => h.rule.weight > 0 && h.end > h.start)
      .sort((a, b) => (b.rule.weight - a.rule.weight) || (a.start - b.start));
    const chosen = [];
    for (const m of marks) {
      if (!chosen.some(c => m.start < c.end && m.end > c.start)) chosen.push(m);
    }
    chosen.sort((a, b) => a.start - b.start);
    let html = '', cursor = 0;
    for (const m of chosen) {
      if (m.start < cursor) continue;
      html += esc(text.slice(cursor, m.start));
      const cls = m.rule.weight >= 6 ? '' : 'warn-level';
      const title = m.rule.label + ' — ' + m.rule.detail;
      html += `<mark class="threat-highlight ${cls}" title="${esc(title)}">${esc(text.slice(m.start, m.end))}</mark>`;
      cursor = m.end;
    }
    html += esc(text.slice(cursor));
    return html;
  }

  /* ----------------------------------------------------------
     6. Link-context rules (internal, keeps module standalone)
     ---------------------------------------------------------- */
  function analyzeEmbeddedLinks(text) {
    const urls = extractUrls(text);
    const triggers = [];
    const legitimacies = [];
    const seen = new Set();
    urls.forEach(u => {
      const host = u.host;
      if (!host) return;
      const tld = tldOf(host);
      if (SUSPICIOUS_TLDS.includes(tld) && !seen.has('tld-' + host)) {
        seen.add('tld-' + host);
        triggers.push({ id: 'l-suspicious-tld', category: 'link', label: 'Link on a risky TLD', detail: `${host} uses .${tld} — cheap, frequently burnt domains.`, weight: 8, text: u.raw, start: u.start, end: u.end });
      }
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host.split(':')[0]) && !seen.has('ip-' + host)) {
        seen.add('ip-' + host);
        triggers.push({ id: 'l-ip-link', category: 'link', label: 'Raw-IP link', detail: `${host} is a bare IP address — no legitimate bank or brand links to an IP.`, weight: 9, text: u.raw, start: u.start, end: u.end });
      }
      if (/(^|\.)xn--/.test(host) && !seen.has('puny-' + host)) {
        seen.add('puny-' + host);
        triggers.push({ id: 'l-punycode-link', category: 'link', label: 'Punycode link', detail: `${host} contains punycode — likely a homoglyph lookalike of a real brand.`, weight: 10, text: u.raw, start: u.start, end: u.end });
      }
      if (SHORTENERS.some(s => host === s) && !seen.has('short-' + host)) {
        seen.add('short-' + host);
        triggers.push({ id: 'l-shortener-link', category: 'link', label: 'Shortened destination', detail: `${host} masks the true destination.`, weight: 6, text: u.raw, start: u.start, end: u.end });
      }
      const flat = normalizeHomoglyphs(host.replace(/\.[a-z]+$/, '').replace(/^www\./, '').replace(/[^a-z0-9]/g, ''));
      for (const brand of BRANDS) {
        if (brand.length < 5 || host.includes(brand)) continue;
        if (levenshtein(flat, brand) <= 1) {
          if (!seen.has('look-' + host)) {
            seen.add('look-' + host);
            triggers.push({ id: 'l-lookalike-link', category: 'link', label: 'Lookalike link', detail: `${host} is a near-miss of ${brand}.com.`, weight: 9, text: u.raw, start: u.start, end: u.end });
          }
          break;
        }
      }
      if (isTrustedHost(host)) {
        legitimacies.push({ id: 'lg-trusted-domain', weight: 6, label: 'Verified domain link', detail: `${host} is on the trusted-domain allowlist.` });
      }
    });
    return { urls, triggers, legitimacies };
  }

  /* ----------------------------------------------------------
     7. Neural layer (lazy, real, optional)
     ---------------------------------------------------------- */
  const neuralState = { status: 'idle', progress: 0, file: '', error: null, labels: null, modelId: NEURAL_MODEL_ID };
  let transformerPromise = null;
  let transformerPipe = null;

  async function loadNeuralModel(onProgress) {
    if (neuralState.status === 'ready') return neuralState;
    if (transformerPromise) return transformerPromise;

    transformerPromise = (async () => {
      neuralState.status = 'loading';
      neuralState.error = null;
      try {
        const mod = await import(TRANSFORMERS_CDN);
        mod.env.allowLocalModels = false;
        if (mod.env.backends && mod.env.backends.onnx && mod.env.backends.onnx.wasm) {
          mod.env.backends.onnx.wasm.numThreads = 1;
        }
        const pipe = await mod.pipeline('text-classification', NEURAL_MODEL_ID, {
          dtype: 'q8',
          progress_callback: (p) => {
            if (!p) return;
            if (p.status === 'progress' && typeof p.progress === 'number') {
              neuralState.progress = Math.round(p.progress);
              neuralState.file = p.file || '';
            } else if (p.status === 'done') {
              neuralState.file = p.file || '';
            }
            if (typeof onProgress === 'function') onProgress(neuralState);
          }
        });
        transformerPipe = pipe;
        neuralState.status = 'ready';
        neuralState.progress = 100;
        return neuralState;
      } catch (err) {
        neuralState.status = 'unavailable';
        neuralState.error = err && err.message ? err.message : String(err);
        transformerPromise = null;
        return neuralState;
      }
    })();
    return transformerPromise;
  }

  async function classifyWithNeural(text) {
    if (neuralState.status !== 'ready' || !transformerPipe) return null;
    try {
      const clipped = String(text).slice(0, 1500);
      const out = await transformerPipe(clipped, { top_k: 4 });
      const arr = Array.isArray(out) ? out : [out];
      /* cybersectony 4-class head → LABEL_0 safe-email, LABEL_1 phishing-email,
         LABEL_2 safe-url, LABEL_3 phishing-url */
      const byLabel = {};
      arr.forEach(r => { byLabel[r.label] = r.score; });
      const pPhish = (byLabel.LABEL_1 || 0) + (byLabel.LABEL_3 || 0);
      neuralState.labels = byLabel;
      return { phishingProb: pPhish, labels: byLabel, model: NEURAL_MODEL_ID };
    } catch (e) {
      return null;
    }
  }

  /* ----------------------------------------------------------
     8. Main analysis
     ---------------------------------------------------------- */
  const CATEGORY_META = {
    urgency: { label: 'Coercive urgency', icon: 'timer' },
    authority: { label: 'Authority impersonation', icon: 'badge-check' },
    credentials: { label: 'Credential harvesting', icon: 'key-round' },
    financial: { label: 'Financial extraction', icon: 'banknote' },
    coercion: { label: 'Threats & isolation', icon: 'lock' },
    remote: { label: 'Remote-access trap', icon: 'monitor-smartphone' },
    job: { label: 'Job / task scam', icon: 'briefcase-business' },
    delivery: { label: 'Delivery scam', icon: 'package' },
    prize: { label: 'Prize bait', icon: 'gift' },
    link: { label: 'Malicious link pattern', icon: 'link' },
    sender: { label: 'Sender anomaly', icon: 'at-sign' },
    context: { label: 'Social-engineering context', icon: 'message-square' }
  };

  function analyze(subject, sender, body) {
    /* Allow (body) or (sender, body) shorthand */
    if (body === undefined) { body = sender || ''; sender = ''; }
    if (subject === undefined || subject === null) subject = '';
    subject = String(subject); body = String(body || ''); sender = String(sender || '');

    const fullText = (subject ? subject + '\n' : '') + body;

    /* --- rule hits --- */
    const bodyHits = scanRules(body, RULES, true);
    const subjectHits = scanRules(subject, RULES, false);
    const senderInfo = analyzeSender(sender);
    const linkInfo = analyzeEmbeddedLinks(fullText);

    /* --- legit signals --- */
    const legitHits = [];
    const seenLegit = new Set();
    scanRules(fullText, LEGIT_SIGNALS, false).forEach(h => {
      if (!seenLegit.has(h.rule.id)) { seenLegit.add(h.rule.id); legitHits.push({ id: h.rule.id, label: h.rule.label, detail: h.rule.detail, weight: h.rule.weight, text: h.text }); }
    });
    linkInfo.legitimacies.forEach(l => { if (!seenLegit.has(l.id)) { seenLegit.add(l.id); legitHits.push(l); } });

    /* --- consolidate rule triggers (dedupe by rule id) --- */
    const triggerMap = new Map();
    const pushTrigger = (h) => {
      const key = h.rule ? h.rule.id : h.id;
      if (triggerMap.has(key)) {
        const existing = triggerMap.get(key);
        existing.occurrences += 1;
        return;
      }
      triggerMap.set(key, {
        id: key,
        category: h.rule ? h.rule.category : h.category,
        categoryLabel: (CATEGORY_META[h.rule ? h.rule.category : h.category] || {}).label || 'Signal',
        label: h.rule ? h.rule.label : h.label,
        detail: h.rule ? h.rule.detail : h.detail,
        weight: h.rule ? h.rule.weight : h.weight,
        text: h.text,
        severity: (h.rule ? h.rule.weight : h.weight) >= 6 ? 'danger' : 'warn',
        occurrences: 1
      });
    };
    bodyHits.forEach(pushTrigger);
    subjectHits.forEach(pushTrigger);
    linkInfo.triggers.forEach(pushTrigger);
    senderInfo.signals.forEach(s => {
      if (!triggerMap.has(s.id)) {
        triggerMap.set(s.id, {
          id: s.id, category: 'sender', categoryLabel: CATEGORY_META.sender.label,
          label: s.label, detail: s.detail, weight: s.weight, text: senderInfo.address || sender,
          severity: s.weight >= 6 ? 'danger' : 'warn', occurrences: 1
        });
      }
    });

    /* Reply-to divergence written inside the body */
    const replyMatch = fullText.match(/(?:reply|respond|write)\s+(?:directly\s+)?to\s+(?:my\s+)?(?:alternate\s+)?(?:inbox\s+)?(?:at\s+)?([\w.+-]+@([\w.-]+\.\w+))/i);
    if (replyMatch && senderInfo.domain) {
      const replyDomain = replyMatch[2].toLowerCase();
      if (replyDomain !== senderInfo.domain && !replyDomain.endsWith('.' + senderInfo.domain)) {
        triggerMap.set('s-reply-mismatch', {
          id: 's-reply-mismatch', category: 'sender', categoryLabel: CATEGORY_META.sender.label,
          label: 'Reply-to divergence', detail: `Reply address ${replyMatch[1]} leaves the sender domain (${senderInfo.domain}).`,
          weight: 6, text: replyMatch[0], severity: 'danger', occurrences: 1
        });
      }
    }

    const triggers = Array.from(triggerMap.values()).sort((a, b) => b.weight - a.weight);

    /* --- points & score --- */
    let points = 0;
    triggers.forEach(t => { points += t.weight * Math.min(1.7, 1 + 0.35 * (t.occurrences - 1)); });

    let legitPoints = 0;
    legitHits.forEach(l => { legitPoints += l.weight; });
    /* Safety advice only cancels OTP-shaped risk, it must not whitewash a wire-fraud email */
    const isProtectiveOtp = legitHits.some(l => l.id === 'lg-never-share' || l.id === 'lg-never-ask');
    if (isProtectiveOtp) {
      ['c-otp-request', 'c-mfa', 'm-otp-numeric'].forEach(id => {
        const t = triggers.find(x => x.id === id);
        if (t && t.weight < 9) t.weight = 0;
      });
    }
    const baseScore = 100 * (1 - Math.exp(-points / 26));
    let score = baseScore - legitPoints * 0.62;
    if (legitPoints > 0 && triggers.length === 0) score = 0;

    /* ---- Categorical override ----------------------------------------
       No legitimate party ever asks you to hand over an OTP, a UPI/ATM PIN,
       a private key or a card CVV. When one of those rules fires *and* the
       message is not carrying protective "never share" language, the intent
       is unambiguous — so the verdict is FALSE even in a very short message
       where there is not enough text to accumulate a high average score. */
    const CATEGORICAL = ['c-otp-request', 'c-pin-request', 'c-seed-phrase', 'c-card-details'];
    const categoricalHit = triggers.some(t => CATEGORICAL.includes(t.id) && t.weight >= 8);
    if (categoricalHit && !isProtectiveOtp) {
      score = Math.max(score, 68);
    }

    score = Math.max(0, Math.min(100, Math.round(score)));

    /* --- category aggregation --- */
    const categories = {};
    Object.keys(CATEGORY_META).forEach(k => { categories[k] = { key: k, label: CATEGORY_META[k].label, icon: CATEGORY_META[k].icon, points: 0, count: 0 }; });
    triggers.forEach(t => {
      if (!categories[t.category]) categories[t.category] = { key: t.category, label: t.categoryLabel, icon: 'alert-triangle', points: 0, count: 0 };
      categories[t.category].points += t.weight;
      categories[t.category].count += 1;
    });
    const categoryList = Object.values(categories).filter(c => c.count > 0)
      .map(c => Object.assign({}, c, { strength: Math.min(100, Math.round(c.points * 4.2)) }))
      .sort((a, b) => b.points - a.points);

    /* --- confidence --- */
    let confidence = 0.58 + Math.min(0.34, triggers.length * 0.04) + Math.min(0.06, legitHits.length * 0.015);
    confidence = Math.max(0.5, Math.min(0.985, confidence));

    /* --- plain-English reasoning --- */
    const reasons = [];
    if (triggers.length === 0) {
      reasons.push({ tone: 'safe', text: 'No manipulation pattern from the 60+ family rulebook matched this message.' });
    } else {
      const topCats = categoryList.slice(0, 3).map(c => c.label.toLowerCase());
      reasons.push({ tone: score >= 60 ? 'danger' : 'warn', text: `Matched ${triggers.length} intent signature${triggers.length > 1 ? 's' : ''} across ${topCats.join(', ')}.` });
      triggers.slice(0, 4).forEach(t => reasons.push({ tone: t.severity, text: `${t.label}: ${t.detail}` }));
    }
    if (legitHits.length) {
      reasons.push({ tone: 'safe', text: `Protective/legitimate language detected: ${legitHits.map(l => l.label).join(', ')} — risk reduced by ${Math.round(legitPoints)} pts.` });
    }

    /* --- highlighted HTML --- */
    const highlightedHtml = buildHighlights(body, bodyHits);

    return {
      engine: 'nlp-semantic-intent-v2',
      model: '60+ weighted pattern families + sender forensics',
      score,
      confidence,
      triggers,
      highlightedHtml,
      categories: categoryList,
      categoryMap: categories,
      legitSignals: legitHits,
      legitPoints,
      extractedUrls: linkInfo.urls.map(u => u.url),
      extractedPhones: extractPhones(fullText),
      sender: senderInfo,
      reasons,
      stats: {
        characters: fullText.length,
        words: (fullText.trim().match(/\S+/g) || []).length,
        rulesEvaluated: RULES.length + LEGIT_SIGNALS.length,
        matchedRules: triggers.length,
        rawPoints: Math.round(points),
        neuralScore: null
      },
      neural: {
        status: neuralState.status,
        model: NEURAL_MODEL_ID,
        progress: neuralState.progress
      }
    };
  }

  /* ----------------------------------------------------------
     9. Public API
     ---------------------------------------------------------- */
  window.NLPEngine = {
    analyze,
    analyzeSender,
    extractUrls,
    extractPhones,
    loadNeuralModel,
    classifyWithNeural,
    getNeuralState: () => Object.assign({}, neuralState, { ready: neuralState.status === 'ready' }),
    RULE_COUNT: RULES.length,
    LEGIT_RULE_COUNT: LEGIT_SIGNALS.length,
    RULES,
    CATEGORY_META
  };

  /* PRD-specified signature */
  window.analyzeEmailNLP = function (subject, sender, body) {
    return analyze(subject, sender, body);
  };
})();
