const { chromium } = require('playwright');

async function run(label, blockAll) {
  const b = await chromium.launch({ args: ['--no-sandbox'] });
  const ctx = await b.newContext({ viewport: { width: 1440, height: 900 } });
  const p = await ctx.newPage();
  if (blockAll) {
    // simulate: no internet, every external host unreachable
    await ctx.route('**/*', route => {
      const u = route.request().url();
      if (u.startsWith('file://') || u.includes('127.0.0.1')) return route.continue();
      return route.abort('internetdisconnected');
    });
  }
  const errs = [];
  p.on('pageerror', e => errs.push(e.message.slice(0, 120)));
  p.on('console', m => { if (m.type() === 'error') errs.push('console: ' + m.text().slice(0, 110)); });

  await p.goto('file:///home/user/xerox-website/index.html', { waitUntil: 'load', timeout: 20000 }).catch(e => console.log('nav fail', e.message.slice(0,80)));
  await p.waitForTimeout(2500);

  const s = await p.evaluate(() => ({
    heading: getComputedStyle(document.querySelector('h1')).fontFamily.split(',')[0],
    h1Size: getComputedStyle(document.querySelector('h1')).fontSize,
    iconsRendered: document.querySelectorAll('svg.lucide').length,
    iconsPending: document.querySelectorAll('i[data-lucide]').length,
    navBg: getComputedStyle(document.querySelector('.xr-navbar')).backgroundColor,
    cardBorder: getComputedStyle(document.querySelector('.glass-card')).borderColor,
    bgCycler: typeof window.XEROXBackground,
    auroraOrbs: document.querySelectorAll('#xr-aurora .xr-orb').length
  }));
  console.log(`\n### ${label}`);
  console.log('  ' + JSON.stringify(s));
  console.log('  errors: ' + (errs.length ? [...new Set(errs)].slice(0,4).join(' | ') : 'none'));
  await p.screenshot({ path: `/home/user/offline-${blockAll ? 'blocked' : 'online'}.png` });
  await b.close();
}

(async () => {
  await run('ONLINE (normal)', false);
  await run('OFFLINE (all CDNs blocked)', true);
})();
