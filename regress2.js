const { chromium } = require('playwright');

(async () => {
  const b = await chromium.launch({ args: ['--no-sandbox'] });

  // ---- A. every page under file:// ----
  console.log('=== file:// (VS Code double-click) ===');
  for (const pg of ['index','scanner','architecture','training']) {
    const p = await (await b.newContext({ viewport: { width: 1440, height: 900 } })).newPage();
    const errs = [];
    p.on('pageerror', e => errs.push(e.message.slice(0, 90)));
    p.on('console', m => { if (m.type() === 'error') errs.push(m.text().slice(0, 90)); });
    await p.goto(`file:///home/user/xerox-website/${pg}.html`, { waitUntil: 'load' });
    await p.waitForTimeout(1600);
    const s = await p.evaluate(() => ({
      icons: document.querySelectorAll('svg.lucide').length,
      pending: document.querySelectorAll('i[data-lucide]').length,
      nav: !!document.querySelector('.xr-navbar'),
      footer: !!document.querySelector('.xr-footer'),
      cycler: typeof window.XEROXBackground,
      h1: getComputedStyle(document.querySelector('h1')).fontSize
    }));
    console.log(`  ${pg.padEnd(12)} icons=${s.icons} pending=${s.pending} nav=${s.nav} footer=${s.footer} cycler=${s.cycler} h1=${s.h1} errors=${errs.length ? errs.join('|') : 'none'}`);
    await p.close();
  }

  // ---- B. scanner works from file:// (engine + presets) ----
  console.log('\n=== scanner engine under file:// ===');
  const sp = await (await b.newContext({ viewport: { width: 1440, height: 1000 } })).newPage();
  const spErrs = [];
  sp.on('pageerror', e => spErrs.push(e.message.slice(0, 100)));
  await sp.goto('file:///home/user/xerox-website/scanner.html', { waitUntil: 'load' });
  await sp.waitForTimeout(1800);
  console.log('  preset buttons:', await sp.locator('.preset-btn[data-preset]').count());
  let pass = 0;
  for (const id of ['sms-kyc','ceo-wire','digital-arrest','punycode-url','upi-qr','dom-stealer','otp-safe','work-email']) {
    const before = await sp.locator('#stat-score').innerText();
    await sp.click(`.preset-btn[data-preset="${id}"]`);
    await sp.waitForFunction(x => { const s = document.querySelector('#stat-score'); return s && s.textContent.trim() !== x; }, before, { timeout: 30000 }).catch(()=>{});
    await sp.waitForTimeout(400);
    const v = await sp.locator('#verdict-badge').innerText();
    const got = v.includes('FALSE') ? 'FALSE' : v.includes('TRUE') ? 'TRUE' : 'CAUTION';
    const exp = ['otp-safe','work-email'].includes(id) ? 'TRUE' : 'FALSE';
    if (got === exp) pass++; else console.log('   MISMATCH', id, v.replace(/\n/g,' '));
  }
  console.log('  presets:', pass + '/8');
  console.log('  page errors:', spErrs.length ? [...new Set(spErrs)] : 'none');
  await sp.close();

  // ---- C. quick verify on index (lean mode) ----
  console.log('\n=== index quick-verify (lean mode) ===');
  const qp = await (await b.newContext({ viewport: { width: 1440, height: 1000 } })).newPage();
  const qErrs = [];
  qp.on('pageerror', e => qErrs.push(e.message.slice(0, 100)));
  qp.on('console', m => { if (m.type() === 'error') qErrs.push(m.text().slice(0, 100)); });
  await qp.goto('file:///home/user/xerox-website/index.html', { waitUntil: 'load' });
  await qp.waitForTimeout(1800);
  await qp.fill('#qv-input', 'Your account will be blocked, share the OTP with our officer immediately.');
  await qp.click('#qv-btn');
  await qp.waitForFunction(() => document.querySelector('#qv-result .verdict-badge'), { timeout: 25000 });
  await qp.waitForTimeout(800);
  console.log('  verdict:', (await qp.locator('#qv-result .verdict-badge').innerText()).replace(/\n/g,' '));
  console.log('  errors:', qErrs.length ? [...new Set(qErrs)] : 'none');
  await qp.close();

  // ---- D. fonts self-hosted? ----
  console.log('\n=== fonts ===');
  const fp = await (await b.newContext()).newPage();
  await fp.goto('file:///home/user/xerox-website/index.html', { waitUntil: 'load' });
  await fp.waitForTimeout(1500);
  console.log('  heading font:', await fp.evaluate(() => getComputedStyle(document.querySelector('h1')).fontFamily.split(',')[0]));
  console.log('  Inter loaded:', await fp.evaluate(() => document.fonts.check('16px Inter')));
  console.log('  SpaceGrotesk loaded:', await fp.evaluate(() => document.fonts.check('16px "Space Grotesk"')));
  console.log('  JetBrains loaded:', await fp.evaluate(() => document.fonts.check('16px "JetBrains Mono"')));
  await fp.close();

  await b.close();
})();
