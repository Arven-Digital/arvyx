// Local synthetic QA only. No production credentials or browser trace/HAR.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const require = createRequire(import.meta.url);
const {chromium} = require(process.env.ARVYX_SECRET_TEST_PLAYWRIGHT);
const config = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const browser = await chromium.launch({headless: true, executablePath: process.env.ARVYX_SECRET_TEST_CHROMIUM});
try {
  const context = await browser.newContext({
    // Ephemeral test CA is intentionally not installed in the host trust store.
    ignoreHTTPSErrors: true,
    // Simulates Access injection with a locally signed test assertion only.
    extraHTTPHeaders: {'Cf-Access-Jwt-Assertion': config.assertion},
    viewport: {width: 1280, height: 900}
  });
  const page = await context.newPage();
  const messages = [];
  page.on('console', message => messages.push(message.text()));
  page.on('pageerror', error => messages.push(String(error)));
  const sendCount = [];
  page.on('request', request => {
    if (request.url().includes('/secret-delivery/')) assert.equal(request.headers()['authorization'], undefined);
    if (request.url().endsWith('/secret-delivery/send')) sendCount.push(1);
  });
  await page.goto(config.origin + '/dashboard');
  assert.equal(await page.locator('#secret-send').isDisabled(), true);
  assert.equal(await page.locator('#secret-value').getAttribute('type'), 'password');
  assert.equal(await page.locator('#bearer').inputValue(), '');
  await page.locator('#secret-connect').click();
  await page.waitForFunction(() => !document.getElementById('secret-send').disabled);
  await page.locator('#secret-name').fill('anthtropic_auth');
  await page.locator('#secret-value').fill(config.marker);
  await page.locator('#secret-send').click();
  await page.waitForFunction(() => document.getElementById('secret-receipt').textContent.includes(': saved'));
  assert.equal(await page.locator('#secret-value').inputValue(), '');
  assert.equal(sendCount.length, 1);
  await page.locator('#secret-value').fill(config.marker + '-cancelled');
  page.once('dialog', dialog => dialog.dismiss());
  await page.locator('#secret-send').click();
  await page.waitForFunction(() => document.getElementById('secret-receipt').textContent.includes('cancelled'));
  assert.equal(sendCount.length, 1);
  await page.locator('#secret-value').fill(config.marker + '-replacement');
  page.once('dialog', dialog => dialog.accept());
  await page.locator('#secret-send').click();
  await page.waitForFunction(() => document.getElementById('secret-receipt').textContent.includes(': saved'));
  assert.equal(await page.locator('#secret-value').inputValue(), '');
  assert.equal(sendCount.length, 2);
  await page.locator('#secret-status-check').click();
  await page.waitForFunction(() => !document.getElementById('secret-send').disabled);
  assert.equal(sendCount.length, 2);
  const storage = await page.evaluate(() => ({local: {...localStorage}, session: {...sessionStorage}}));
  assert.equal(JSON.stringify(storage).includes(config.marker), false);
  assert.equal(messages.join('\n').includes(config.marker), false);
  assert.equal((await page.content()).includes(config.marker), false);
  if (process.env.ARVYX_SECRET_TEST_SCREENSHOT) {
    await page.evaluate(() => { document.documentElement.style.scrollBehavior = 'auto'; window.scrollTo(0, 0); });
    await page.waitForFunction(() => window.scrollY === 0);
    await page.screenshot({path: process.env.ARVYX_SECRET_TEST_SCREENSHOT});
    await page.setViewportSize({width:390, height:844});
    await page.evaluate(() => { document.documentElement.style.scrollBehavior = 'auto'; window.scrollTo(0, 0); });
    await page.waitForFunction(() => window.scrollY === 0);
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true);
    await page.screenshot({path: process.env.ARVYX_SECRET_TEST_SCREENSHOT.replace(/\.png$/, '-mobile.png')});
  }
  console.log(JSON.stringify({ok:true, sends:sendCount.length, noBrowserCertificate:true, noSharedBearer:true, cancelledOverwrite:true, confirmedOverwrite:true, clearedInput:true, noValueInStorageConsoleDOM:true}));
  await context.close();
} finally {
  await browser.close();
}
