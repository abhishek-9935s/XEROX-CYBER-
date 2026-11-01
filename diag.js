const { chromium } = require('playwright');

async function probe(label, url) {
  const b = await chromium.launch({ args: ['--no-sandbox'] });
  const p = await (await b.newContext({ viewport: { width: 1440, height: 900 } })).newPage();
  const errs = [], warns = [], fails = [];
  p.on('pageerror', e => errs.push(e.message.slice(0, 160)));
  p.on('console', m => {
    if (m.type() === 'error') errs.push('console: ' + m.text().slice(0, 160));
    if (m.type() === 'warning') warns.push(m.text().slice(0, 120));
  });
  p.on('requestfailed', r => fails.push(r.url().slice(0, 90) + ' :: ' + (r.failure() || {}).errorText));

  try {
    await p.goto(url, { waitUntil: 'load', timeout: 20000 });
  } catch (e) {
    console.log(`\n### ${label}\n  NAV FAILED: ${e.message.slice(0, 120)}`);
    await b.close(); return;
  }
  await p.waitForTimeout(2500);

  const probeState = await p.evaluate(() => {
    const q = s => document.querySelector(s);
    const nav = q('.xr-navbar');
    const brand = q('.xr-brand');
    const icons = document.querySelectorAll('svg.lucide').length;
    const rawIcons = document.querySelectorAll('i[data-lucide]').length;
    const aurora = q('#xr-aurora');
    const orbCount = document.querySelectorAll('#xr-aurora .xr-orb').length;
    const h1 = q('h1');
    const heroBg = q('.hero') ? getComputedStyle(q('.hero')).backgroundColor : null;
    const bodyBg = getComputedStyle(document.body).backgroundColor;
    const cssLoaded = getComputedStyle(document.documentElement).getPropertyValue('--accent-orange').trim();
    const bgCycler = typeof window.XEROXBackground;
    const presetCount = document.querySelectorAll('.preset-btn[data-preset]').length;
    return {
      navRendered: !!nav, brand: brand ? brand.innerText.replace(/\n/g,'') : null,
      svgIcons: icons, unrenderedIcons: rawIcons,
      auroraLayer: !!aurora, orbs: orbCount,
      h1Size: h1 ? getComputedStyle(h1).fontSize : null,
      h1Text: h1 ? h1.innerText.replace(/\n/g,' ').slice(0,40) : null,
      bodyBg, accentToken: cssLoaded, bgCyclerApi: bgCycler, presetButtons: presetCount,
      footer: !!document.querySelector('.xr-footer'), scrollW: document.documentElement.scrollWidth
    };
  });

  console.log(`\n### ${label}`);
  console.log('  ' + JSON.stringify(probeState, null, 1).replace(/\n/g, '\n  '));
  console.log('  JS errors: ' + (errs.length ? '\n    - ' + [...new Set(errs)].slice(0, 6).join('\n    - ') : 'none'));
  console.log('  Failed requests: ' + (fails.length ? '\n    - ' + [...new Set(fails)].slice(0, 6).join('\n    - ') : 'none'));
  await b.close();
}

(async () => {
  // A) double-click index.html  → file://
  await probe('A. file:// double-click', 'file:///home/user/xerox-website/index.html');
  // B) Live Server equivalent (served from project root)
  await probe('B. http:// from project root (Live Server)', 'http://127.0.0.1:8000/index.html');
  // C) Live Server pointed at the PARENT folder
  await probe('C. served from parent folder', 'http://127.0.0.1:8001/xerox-website/index.html');
})();
