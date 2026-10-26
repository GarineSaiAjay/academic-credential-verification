// Drives the sign-in, two-factor, session and password-reset screens in real Chrome against the real server.
// Usage: PASS=<demo password> node e2e/auth-ui.mjs
// The stack must run on http://localhost:3000 with REQUIRE_MFA_ROLES=registrar, on a fresh database.
import { chromium } from 'playwright-core';
import { createHmac } from 'node:crypto';
const BASE = process.env.BASE || 'http://localhost:3000', API = BASE + '/api/v1', PASS = process.env.PASS;
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
const login = async (u, p = PASS) => (await api('POST', '/auth/login', null, { email: u + '@university.edu', password: p })).body.token;

// RFC 6238, the same computation an authenticator app does.
function totp(secret, offset = 0) {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of secret) bits += A.indexOf(c).toString(2).padStart(5, '0');
  const key = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000) + offset));
  const h = createHmac('sha1', key).update(counter).digest();
  const o = h[19] & 15;
  return String(((h.readUInt32BE(o) & 0x7fffffff) % 1000000)).padStart(6, '0');
}

async function newPage(browser) {
  const page = await (await browser.newContext()).newPage();
  page.on('dialog', (d) => d.accept(d.defaultValue()));
  return page;
}
async function signIn(page, user, pass = PASS) {
  await page.goto(BASE + '/#/login');
  await page.getByLabel('Email').fill(user + '@university.edu');
  await page.getByLabel('Password').fill(pass);
  await page.getByRole('button', { name: 'Sign in' }).click();
}
const signedIn = (page, user) => page.getByText(user + '@university.edu').first().waitFor({ timeout: 10000 });
async function signOut(page) { await page.getByRole('link', { name: 'logout' }).click(); await page.getByRole('heading', { name: 'Sign in' }).or(page.getByText('Sign in').first()).first().waitFor(); }

const browser = await chromium.launch({ channel: 'chrome', headless: true });
try {
  const adm = await login('admin');

  console.log('== password reset link');
  const fid = (await api('GET', '/users', adm)).body.users.find((u) => u.email === 'faculty@university.edu').id;
  const link = (await api('POST', `/users/${fid}/reset-link`, adm)).body.path;
  const p = await newPage(browser);
  await p.goto(BASE + link);
  await p.getByLabel('New password').fill('Password1234');
  await p.getByLabel('Again').fill('Password1234');
  await p.getByRole('button', { name: 'Set password' }).click();
  await p.locator('.notice.err').waitFor();
  check('a weak password is refused on the page', /too easy to guess/.test(await p.locator('.notice.err').innerText()));
  await p.getByLabel('New password').fill('ui reset passphrase 42');
  await p.getByLabel('Again').fill('ui reset passphrase 4');
  await p.getByRole('button', { name: 'Set password' }).click();
  check('mismatched passwords are caught', /differ/.test(await p.locator('.notice.err').innerText()));
  await p.getByLabel('Again').fill('ui reset passphrase 42');
  await p.getByRole('button', { name: 'Set password' }).click();
  await p.getByText('Password changed').first().waitFor();
  ok('the link sets the password');
  await p.goto(BASE + '/#/login');
  await p.goto(BASE + link);
  await p.reload();
  await p.getByLabel('New password').fill('another passphrase 43 x');
  await p.getByLabel('Again').fill('another passphrase 43 x');
  await p.getByRole('button', { name: 'Set password' }).click();
  await p.locator('.notice.err').waitFor();
  check('the same link does not work twice', /not valid|already used/.test(await p.locator('.notice.err').innerText()));
  await signIn(p, 'faculty', 'ui reset passphrase 42');
  await signedIn(p, 'faculty');
  ok('and the person signs in with the new password');

  console.log('== sessions page');
  const other = await login('faculty', 'ui reset passphrase 42');
  await p.goto(BASE + '/#/account');
  await p.getByText('Where you are signed in').waitFor();
  await p.locator('tbody tr', { hasText: '(this one)' }).waitFor();
  check('lists this device and the other one', (await p.locator('tr', { has: p.locator('td.mono') }).count()) >= 2);
  const rows = p.locator('table').filter({ hasText: 'Signed in' }).locator('tbody tr');
  await rows.filter({ hasNot: p.getByText('(this one)') }).first().getByRole('button', { name: 'Sign out' }).click();
  await p.getByText('Session ended').waitFor();
  check('signing out another session ends it', (await api('GET', '/auth/me', other)).code === 401);
  await signOut(p);

  console.log('== a role that must use two-factor sign-in');
  await signIn(p, 'registrar');
  await p.getByText('Your role must sign in with a second factor').waitFor();
  ok('is sent to set it up on first sign-in');
  check('and the rest of the app is hidden', (await p.getByRole('link', { name: 'Credentials' }).count()) === 0);
  await p.getByLabel('Your password').fill(PASS);
  await p.getByRole('button', { name: 'Set up' }).click();
  await p.getByAltText('QR code for your authenticator app').waitFor();
  ok('shows a QR code');
  const secret = (await p.locator('span.mono').first().innerText()).trim();
  check('and the key as text', /^[A-Z2-7]{32}$/.test(secret));
  await p.getByLabel('Code from the app').fill('000000');
  await p.getByRole('button', { name: 'Turn on' }).click();
  await p.locator('.notice.err').waitFor();
  ok('a wrong code is refused');
  await p.getByLabel('Code from the app').fill(totp(secret));
  await p.getByRole('button', { name: 'Turn on' }).click();
  await p.getByText('Recovery codes.').waitFor();
  const recovery = (await p.locator('pre.mono').innerText()).trim().split('\n');
  check('ten recovery codes are shown', recovery.length === 10);
  await p.getByRole('button', { name: 'I have saved them' }).click();
  await p.getByRole('link', { name: 'Credentials' }).waitFor();
  ok('then the restriction lifts without signing in again');
  check('a required role has no way to turn it off', (await p.getByRole('button', { name: 'Turn off' }).count()) === 0);
  await signOut(p);

  await signIn(p, 'registrar');
  await p.getByText('Enter the 6-digit code').waitFor();
  ok('the next sign-in asks for the code');
  await p.getByLabel('Code').fill('123456');
  await p.getByRole('button', { name: 'Sign in' }).click();
  await p.locator('.notice.err').waitFor();
  check('a wrong code is refused', /not valid/.test(await p.locator('.notice.err').innerText()));
  await p.getByLabel('Code').fill(totp(secret, 1));
  await p.getByRole('button', { name: 'Sign in' }).click();
  await signedIn(p, 'registrar');
  ok('the right code signs in');
  await signOut(p);
  await signIn(p, 'registrar');
  await p.getByLabel('Code').fill(recovery[0]);
  await p.getByRole('button', { name: 'Sign in' }).click();
  await signedIn(p, 'registrar');
  ok('a recovery code signs in');
  await p.goto(BASE + '/#/account');
  await p.getByText('9 recovery code(s) left').waitFor();
  ok('and is used up');

  console.log('== administrator');
  const a = await newPage(browser);
  await signIn(a, 'admin');
  await signedIn(a, 'admin');
  await a.goto(BASE + '/#/users');
  const row = a.locator('tr', { hasText: 'registrar@university.edu' });
  await row.getByText('on', { exact: true }).waitFor();
  ok('the user list shows who has two-factor sign-in');
  await row.getByRole('button', { name: 'Reset 2FA' }).click();
  await a.getByText('Two-factor sign-in removed for registrar@university.edu').waitFor();
  const regNow = await api('POST', '/auth/login', null, { email: 'registrar@university.edu', password: PASS });
  check('resetting it makes the role set it up again', regNow.body.mfa_setup_required === true);
  await row.getByRole('button', { name: 'Reset link' }).click();
  await a.getByText('Reset link issued for registrar@university.edu').waitFor();
  ok('the Reset link button issues a link');
} catch (e) {
  bad(String(e && e.stack || e));
} finally {
  await browser.close();
}
console.log(fails ? `\n${fails} CHECK(S) FAILED` : '\nALL AUTH UI CHECKS PASSED');
process.exit(fails ? 1 : 0);
