// Runs against the actual generated API registration + gateway + compiled UI.
// The card and archive are a typed mock fixture; this is not platform proof.
import { chromium } from '/root/.local/share/playwright-cli/node_modules/playwright/index.mjs';
import assert from 'node:assert/strict';
import { mkdir } from 'node:fs/promises';
const [url, card, filename] = process.argv.slice(2);
const evidence = process.env.TSW_BROWSER_EVIDENCE;
const browser = await chromium.launch({ executablePath: '/root/.cache/ms-playwright/chromium-1243/chrome-linux64/chrome', headless: true, args: ['--no-sandbox'] });
try {
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 1000 }, acceptDownloads: true });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await page.goto(`${url}/redeem/`);
  const input = page.getByRole('textbox', { name: '卡密', exact: true });
  await input.fill(card);
  await page.getByRole('button', { name: '领取', exact: true }).click();
  const download = page.getByRole('button', { name: '下载原交付 ZIP', exact: true });
  await download.waitFor();
  assert.equal(await page.getByText('可下载', { exact: true }).count(), 1);
  const typography = await page.evaluate(() => {
    const roles = { brand: 'header p', label: '.mantine-InputWrapper-label', button: '.mantine-Button-root', badge: '.mantine-Badge-root', title: 'h1, h2' };
    const emphasized = Object.fromEntries(Object.entries(roles).map(([name, selector]) => [name, [...document.querySelectorAll(selector)].map((element) => getComputedStyle(element).fontWeight)]));
    const weights = [...new Set([...document.querySelectorAll('.public-shell *')].filter((element) => element.getBoundingClientRect().height > 0 && [...element.childNodes].some((node) => node.nodeType === Node.TEXT_NODE && node.textContent.trim())).map((element) => getComputedStyle(element).fontWeight))].sort();
    return { emphasized, weights };
  });
  assert.deepEqual(typography.weights, ['400', '600']);
  for (const [role, weights] of Object.entries(typography.emphasized)) { assert.ok(weights.length > 0, role); assert.ok(weights.every((weight) => weight === '600'), JSON.stringify({ role, weights })); }

  if (evidence) { await mkdir(evidence, { recursive: true }); await page.screenshot({ path: `${evidence}/public-ready-desktop.png`, fullPage: true }); }
  const first = page.waitForEvent('download');
  await download.click();
  assert.equal((await first).suggestedFilename(), filename);
  await page.reload();
  await download.waitFor();
  // A recovered browser cookie shows the original order without re-entering a
  // card. One server ZIP is still the only download action.
  assert.equal(await download.count(), 1);
  await input.fill(card);
  await page.getByRole('button', { name: '找回原交付', exact: true }).click();
  await page.getByText('已找回原交付', { exact: true }).waitFor();
  await page.getByRole('button', { name: '查看状态', exact: true }).click();
  await download.waitFor();
  // A network download failure retains the same original order and input.
  await page.route('**/api/public/v1/redeem/download', (route) => route.abort('failed'));
  await download.click();
  await page.getByRole('alert').filter({ hasText: '操作未完成' }).waitFor();
  assert.equal(await input.inputValue(), card);
  assert.equal(await download.count(), 1);
  await page.unroute('**/api/public/v1/redeem/download');
  await input.fill('TSW1-d3JvbmdjYXJkd3JvbmdjYXJkMTI');
  await page.getByRole('button', { name: '领取', exact: true }).click();
  await page.getByRole('alert').filter({ hasText: '当前卡密或领取授权不可用' }).waitFor();
  assert.equal(await download.count(), 0);
  if (evidence) { await mkdir(evidence, { recursive: true }); await page.screenshot({ path: `${evidence}/public-invalid-desktop.png`, fullPage: true }); }
  await page.setViewportSize({ width: 390, height: 844 });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  if (evidence) await page.screenshot({ path: `${evidence}/public-invalid-narrow.png`, fullPage: true });
  await input.focus();
  assert.equal(await input.evaluate((element) => element === document.activeElement), true);
  assert.deepEqual(errors, []);
  console.log(JSON.stringify({ browser: browser.version(), registeredGateway: true, compiledMantinePublic: true, typography, originalZIP: filename, cases: ['claim', 'download', 'refresh original', 'card recovery', 'status', 'download network failure preserves original', 'invalid card', 'narrow layout', 'keyboard focus'], platform: 'mock only' }));
  await context.close();
} finally { await browser.close(); }
