const { chromium } = require('playwright');

async function run(label, blockExternal) {
  const b = await chromium.launch({ args: ['--no-sandbox'] });
  const ctx = await b.newContext({ viewport: { width: 1440, height: 900 } });
  const p = await ctx.newPage();
  if (blockExternal) {
    await ctx.route('**/*', r => {
      const u = r.request().url();
      if (u.startsWith('file://') || u.includes('127.0.0.1')) return r.continue();
      return r.abort('internetdisconnected');
    });
  }
  const errs = [];
  p.on('pageerror', e => errs.push(e.message.slice(0, 110)));
  p.on('console', m => { if (m.type() === 'error') errs.push('console: ' + m.text().slice(0, 100)); });

  await p.goto('file:///home/user/xerox-website/index.html', { waitUntil: 'load', timeout: 20000 });
  await p.waitForTimeout(2200);
  const s = await p.evaluate(() => ({
    icons: document.querySelectorAll('svg.lucide').length,
    pendingIcons: document.querySelectorAll('i[data-lucide]').length,
    brand: (document.querySelector('.xr-brand') || {}).innerText,
    nav: !!document.querySelector('.xr-navbar'),
    h1: getComputedStyle(document.querySelector('h1')).fontSize,
    cycler: typeof window.XEROXBackground,
    orbs: document.querySelectorAll('#xr-aurora .xr-orb').length,
    flexOK: getComputedStyle(document.querySelector('.flex')).display
  }));
  console.log(`\n### ${label}`);
  console.log('  ' + JSON.stringify(s));
  console.log('  errors: ' + (errs.length ? [...new Set(errs)].slice(0, 4).join(' | ') : 'none'));
  await p.screenshot({ path: `/home/user/v2-${blockExternal ? 'offline' : 'online'}.png` });
  await b.close();
}
(async () => { await run('ONLINE', false); await run('OFFLINE (all CDNs blocked)', true); })();
