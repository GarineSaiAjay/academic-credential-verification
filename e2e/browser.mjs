// Drives the real UI in real Chrome with a virtual authenticator (WebAuthn), against the real server.
// Usage: PASS=<demo password> REPO=<repo root> node e2e/browser.mjs   (stack running on http://localhost:3000)
import { chromium } from 'playwright-core';
import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
const BASE = process.env.BASE || 'http://localhost:3000', API = BASE + '/api/v1', PASS = process.env.PASS, REPO = process.env.REPO;
let fails = 0;
const ok = (m) => console.log('  ok   ' + m), bad = (m) => { fails++; console.log('  FAIL ' + m); };
const check = (m, c) => (c ? ok(m) : bad(m));

async function api(method, path, token, body) {
  const h = { 'Content-Type': 'application/json' };
  if (token) h.Authorization = 'Bearer ' + token;
  if (method === 'POST') { h['X-Nonce'] = crypto.randomUUID(); h['X-Timestamp'] = String(Math.floor(Date.now() / 1000)); }
  const r = await fetch(API + path, { method, headers: h, body: body ? JSON.stringify(body) : undefined });
  return { code: r.status, body: await r.json().catch(() => ({})) };
}
const login = async (u) => (await api('POST', '/auth/login', null, { email: u + '@university.edu', password: PASS })).body.token;

async function newSession(browser) {
  const context = await browser.newContext();
  const page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  page.cdp = cdp;
  page.devices = { first: authenticatorId, second: null };
  // With two devices present both would answer at once. A person touches the one they mean, so the test
  // enables only the device the page is about to use: the new one to create a key, the old one to sign.
  await page.exposeFunction('__touch', async (which) => {
    if (!page.devices.second) return;
    await cdp.send('WebAuthn.setAutomaticPresenceSimulation', { authenticatorId: page.devices.first, enabled: which === 'first' });
    await cdp.send('WebAuthn.setAutomaticPresenceSimulation', { authenticatorId: page.devices.second, enabled: which === 'second' });
  });
  await page.addInitScript(() => {
    const creds = navigator.credentials, create = creds.create.bind(creds), get = creds.get.bind(creds);
    creds.create = async (o) => { await window.__touch('second'); return create(o); };
    creds.get = async (o) => { await window.__touch('first'); return get(o); };
  });
  page.on('dialog', (d) => d.accept());
  return page;
}
// A second, separate device (like plugging in another security key).
async function addDevice(page) {
  const { authenticatorId } = await page.cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'usb', hasResidentKey: false, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  page.devices.second = authenticatorId;
}
async function uiLogin(page, user) {
  await page.goto(BASE + '/#/login');
  await page.getByLabel('Email').fill(user + '@university.edu');
  await page.getByLabel('Password').fill(PASS);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.getByText(user + '@university.edu').first().waitFor();
}
async function uiRegister(page, label) {
  await page.goto(BASE + '/#/account');
  await page.getByLabel(/Name for the new key/).fill(label);
  await page.getByRole('button', { name: 'Add a security key / passkey' }).click();
  const done = await Promise.race([
    page.getByText('Key added').waitFor({ timeout: 15000 }).then(() => 'ok'),
    page.locator('.notice.err').first().waitFor({ timeout: 15000 }).then(async () => 'error: ' + (await page.locator('.notice.err').first().innerText())),
  ]).catch(() => 'timed out waiting for the page to answer');
  if (done !== 'ok') throw new Error('registering "' + label + '" failed: ' + done);
  await page.getByRole('cell', { name: label, exact: true }).first().waitFor();
}

const browser = await chromium.launch({ channel: 'chrome', headless: true });
try {
  const fac = await login('faculty'), exc = await login('examcell');
  for (const [name, token] of [['faculty', fac], ['examcell', exc]]) {
    if ((await api('GET', '/me/keys', token)).body.keys.length) throw new Error(`${name} already has security keys; run this against a fresh stack`);
  }
  const created = await api('POST', '/credentials', fac, { student_id: 'BR-1', student_name: 'Browser Test', program: 'BSc', graduation_date: '2025-05-15' });
  const id = created.body.id;

  console.log('== exam cell: register a key and approve in the real UI');
  const p1 = await newSession(browser);
  await uiLogin(p1, 'examcell');
  const examLabel = 'Chrome virtual key ' + Date.now();
  await uiRegister(p1, examLabel);
  ok('registered a key through the Account page');
  const keys = await api('GET', '/me/keys', exc);
  check('the server lists the new key as active', keys.body.keys.some((k) => k.label === examLabel && k.status === 'active'));
  await p1.goto(BASE + '/#/c/' + id);
  const signBtn = p1.getByRole('button', { name: /Sign as exam cell with my security key/ });
  await signBtn.waitFor({ timeout: 15000 });
  ok('the page offers to sign with the security key');
  await signBtn.click();
  await p1.getByText('pending registrar').first().waitFor({ timeout: 15000 });
  const v1 = await api('GET', '/verify/' + id);
  check('credential moved to pending registrar', v1.body.credential.status === 'pending_registrar');
  const personal = v1.body.signatures[1].personal;
  check('the approval carries a valid personal signature made by Chrome', personal && personal.valid === true);
  check('signed with user verification and presence', personal && (Buffer.from(personal.authenticator_data, 'base64url')[32] & 5) === 5);
  writeFileSync('/tmp/acvs-browser-verify.json', JSON.stringify(v1.body));
  const out = execFileSync('python3', [REPO + '/scripts/webauthn_sim.py', 'check', '/tmp/acvs-browser-verify.json']).toString().trim();
  check('openssl independently verifies the signature Chrome produced (' + out + ')', out === 'independently verified 1 personal signature(s)');

  console.log('== exam cell: adding a second key needs the first key to approve it');
  const second = 'Second key ' + Date.now();
  await addDevice(p1);
  await uiRegister(p1, second);
  const after = await api('GET', '/me/keys', exc);
  check('the second key was added after the first key approved it', after.body.keys.length === 2 && after.body.keys.every((k) => k.status === 'active'));
  const audit = await api('GET', '/audit?limit=20', await login('admin'));
  check('the audit log records that an existing key approved it', audit.body.logs.some((l) => l.action === 'USER_KEY_REGISTERED' && l.details && l.details.approved_by_existing_key === true));

  console.log('== faculty: add a personal signature to their own approval in the UI');
  const p2 = await newSession(browser);
  await uiLogin(p2, 'faculty');
  await uiRegister(p2, 'Faculty key ' + Date.now());
  await p2.goto(BASE + '/#/c/' + id);
  const cs = p2.getByRole('button', { name: /Add my personal signature/ });
  await cs.waitFor({ timeout: 15000 });
  ok('the page offers the faculty member a personal signature');
  await cs.click();
  await p2.getByText('Personal signature added').waitFor({ timeout: 15000 });
  const v2 = await api('GET', '/verify/' + id);
  check('faculty approval now has a valid personal signature', v2.body.signatures[0].personal && v2.body.signatures[0].personal.valid === true);
  check('the credential is still PENDING (not invalidated)', v2.body.verdict === 'PENDING');
  await p2.reload();
  await p2.getByText(/valid \(key [0-9a-f]{8}\)/).first().waitFor();
  ok('the signatures table shows the personal signatures');
  check('the button is gone once everything is signed', (await p2.getByRole('button', { name: /Add my personal signature/ }).count()) === 0);
  const pub = await newSession(browser);
  await pub.goto(BASE + '/#/verify/' + id);
  await pub.getByText(/valid \(key [0-9a-f]{8}\)/).first().waitFor();
  ok('the public verification page shows them too, without anyone\'s name');
  check('and no staff email appears there', !(await pub.content()).includes('@university.edu'));
} catch (e) {
  bad('browser test crashed: ' + e.message);
} finally {
  await browser.close();
}
console.log(fails ? `\n${fails} CHECK(S) FAILED` : '\nALL BROWSER CHECKS PASSED');
process.exit(fails ? 1 : 0);
