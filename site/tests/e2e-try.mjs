// End-to-end browser check of the Try it page, using Playwright and the real Go command line.
//
// Not part of CI (it needs a browser). Run it by hand before releasing a site version:
//   npm install --no-save playwright && npx playwright install chromium   # once
//   go run ./cmd/sitegen && node site/tests/e2e-try.mjs
//
// It serves docs/ itself, drives the demo (make, download, open, tamper, wrong app, hostile name),
// confirms a file made in the browser is accepted by `goldd packet check`, and confirms the page
// never requests anything outside localhost.
import { createRequire } from "node:module";
import http from "node:http";
import { mkdtempSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import nodePath from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const require = createRequire(import.meta.url);
const { chromium } = require("playwright");
const root = nodePath.resolve(nodePath.dirname(fileURLToPath(import.meta.url)), "../..");
const docs = nodePath.join(root, "docs");
const work = mkdtempSync(nodePath.join(tmpdir(), "gold-e2e-"));
const types = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml", ".gold": "application/json" };

const server = http.createServer((req, res) => {
  const rel = decodeURIComponent(new URL(req.url, "http://x").pathname).replace(/^\/+/, "") || "index.html";
  const file = nodePath.join(docs, rel);
  if (!file.startsWith(docs) || !existsSync(file)) { res.writeHead(404).end(); return; }
  res.writeHead(200, { "content-type": types[nodePath.extname(file)] || "application/octet-stream" }).end(readFileSync(file));
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const BASE = `http://localhost:${server.address().port}`;
const SP = work;
const fs = { readFileSync, writeFileSync };
const path = nodePath;

let fails = 0;
const ok = (c, m) => { console.log((c ? 'PASS ' : 'FAIL ') + m); if (!c) fails++; };
  const b = await chromium.launch();
  const ctx = await b.newContext({ viewport: { width: 1280, height: 900 }, acceptDownloads: true });
  const p = await ctx.newPage();
  const errs = [], external = [];
  p.on('pageerror', e => errs.push(String(e)));
  p.on('console', m => { if (m.type() === 'error') errs.push(m.text()); });
  p.on('request', r => { const u = new URL(r.url()); if (u.hostname !== 'localhost' && u.protocol.startsWith('http')) external.push(r.url()); });
  await p.goto(`${BASE}/try.html`);

  // 1 make
  await p.click('#new-btn');
  ok(await p.isVisible('#current'), 'making a packet shows it');
  ok((await p.textContent('#current-list')).includes('notes-demo'), 'summary shows the app id');
  ok(!(await p.isDisabled('#dl-btn')), 'download is enabled');

  // 2 download, then validate the browser-made file with the GO command line
  const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#dl-btn')]);
  const file1 = path.join(SP, 'from-browser.gold');
  await dl.saveAs(file1);
  ok(dl.suggestedFilename() === 'sam-s-notes.gold', 'download file name is ' + dl.suggestedFilename());
  let goOut = '', goCode = 0;
  try { goOut = execFileSync('go', ['run', './cmd/goldd', 'packet', 'check', '-app', 'notes-demo', file1], { encoding: 'utf8', cwd: root }); } catch (e) { goCode = e.status; goOut = String(e.stdout) + String(e.stderr); }
  ok(goCode === 0 && goOut.startsWith('ok'), 'Go reads the browser-made file with no warnings: ' + goOut.trim().slice(0, 90));

  // 3 open the same file: identical
  await p.setInputFiles('#open-file', file1);
  await p.waitForSelector('#result .bb-notice');
  let res = await p.textContent('#result');
  ok(res.includes('Identical'), 'same file is identical');

  // 4 save a new revision, then open the OLD file: older + separate copy
  await p.fill('#payload', '{"note":"changed"}');
  await p.click('#rev-btn');
  ok((await p.textContent('#current-list')).includes('2'), 'history has 2 revisions');
  await p.setInputFiles('#open-file', file1);
  await p.waitForFunction(() => document.querySelector('#result').textContent.includes('Older'));
  ok(true, 'older file is detected as older');
  await p.click('text=Open as a separate copy');
  ok((await p.textContent('#current-list')).includes('Copied from'), 'separate copy records its origin');

  // 5 tamper with the file text, open: checksum warning
  const tampered = fs.readFileSync(file1, 'utf8').replace("Sam's notes", 'Evil notes');
  const file2 = path.join(SP, 'tampered.gold'); fs.writeFileSync(file2, tampered);
  await p.setInputFiles('#open-file', file2);
  await p.waitForFunction(() => document.querySelector('#result').textContent.includes('Checksum does not match'));
  ok((await p.textContent('#result')).includes('not a signature'), 'tampering warns and says a checksum is not a signature');

  // 6 isolation
  await p.fill('#app-id', 'other-app');
  await p.setInputFiles('#open-file', file1);
  await p.waitForFunction(() => document.querySelector('#result').textContent.includes('app_mismatch'));
  ok(true, 'a packet for another app is refused (app_mismatch)');
  await p.fill('#app-id', 'notes-demo');

  // 7 signed example
  await p.click('#example-btn');
  await p.waitForFunction(() => document.querySelector('#result').textContent.includes('Attestations'));
  res = await p.textContent('#result');
  ok(res.includes('email confirmed by email-reply') && res.includes('does not verify signatures'), 'example shows its attestation, and says signatures are not verified here');
  ok(!res.includes('Checksum does not match'), 'the Go-written example has a valid checksum');

  // 8 hostile name must not execute or become markup
  await p.fill('#name', '<img src=x onerror="window.__pwn=1"><b>bold</b>');
  await p.click('#new-btn');
  const [dl2] = await Promise.all([p.waitForEvent('download'), p.click('#dl-btn')]);
  const file3 = path.join(SP, 'hostile.gold'); await dl2.saveAs(file3);
  await p.setInputFiles('#open-file', file3);
  await p.waitForSelector('#result .bb-card');
  await p.waitForTimeout(300);
  ok(await p.evaluate(() => window.__pwn === undefined), 'hostile name did not execute');
  ok(await p.evaluate(() => document.querySelectorAll('#result img, #result b, #current img, #current b').length === 0), 'hostile name was not turned into markup');
  ok((await p.textContent('#result')).includes('<img src=x'), 'hostile name is shown as plain text');

  // 9 bad data message
  await p.fill('#payload', '[1,2]');
  await p.click('#new-btn');
  ok(await p.isVisible('#make-error') && (await p.getAttribute('#payload', 'aria-invalid')) === 'true', 'bad data shows an error and aria-invalid');

  ok(errs.length === 0, 'no console or page errors ' + JSON.stringify(errs));
  ok(external.length === 0, 'no requests left localhost ' + JSON.stringify(external));

  // layout
  for (const w of [320, 390, 1280]) {
    await p.setViewportSize({ width: w, height: 900 });
    await p.goto(`${BASE}/try.html`);
    const m = await p.evaluate(() => ({ sw: document.documentElement.scrollWidth, iw: innerWidth }));
    ok(m.sw <= m.iw + 1, `try.html has no horizontal overflow at ${w}px`);
  }
  await p.setViewportSize({ width: 390, height: 900 });
  await p.goto(`${BASE}/try.html`); await p.click('#new-btn'); await p.click('#example-btn');
  await p.waitForSelector('#result .bb-card');
  await p.screenshot({ path: SP + '/try-390-b.png', fullPage: true });
  await p.setViewportSize({ width: 1280, height: 1000 });
  await p.screenshot({ path: SP + '/try-1280-b.png', fullPage: false });
  await b.close();
  console.log(fails ? `\n${fails} FAILED` : '\nALL PASSED');
  server.close();
  process.exit(fails ? 1 : 0);
