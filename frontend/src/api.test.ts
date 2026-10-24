import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { api, ApiError, getSession, setSession } from './api';

const reply = (status: number, body: unknown) =>
  vi.fn().mockResolvedValue({ ok: status < 400, status, json: async () => body });
const sent = (f: ReturnType<typeof vi.fn>) => f.mock.calls[0][1] as { method: string; headers: Record<string, string>; body?: string };

beforeEach(() => setSession(null));
afterEach(() => vi.unstubAllGlobals());

describe('api()', () => {
  it('sends the token, and a fresh nonce and timestamp only on writes', async () => {
    setSession({ token: 'tok', email: 'a@b.c', role: 'faculty' });
    const f = reply(200, {});
    vi.stubGlobal('fetch', f);
    await api('GET', '/credentials');
    expect(f.mock.calls[0][0]).toBe('/api/v1/credentials');
    expect(sent(f).headers.Authorization).toBe('Bearer tok');
    expect(sent(f).headers['X-Nonce']).toBeUndefined();
    expect(sent(f).headers['X-Timestamp']).toBeUndefined();

    await api('POST', '/credentials', { a: 1 });
    await api('POST', '/credentials', { a: 1 });
    const [a, b] = [f.mock.calls[1][1], f.mock.calls[2][1]].map((c) => c.headers);
    expect(a['X-Nonce']).toMatch(/^[0-9a-f]{32}$/);
    expect(a['X-Nonce']).not.toBe(b['X-Nonce']);
    expect(Math.abs(Number(a['X-Timestamp']) - Date.now() / 1000)).toBeLessThan(5);
    expect(a['Content-Type']).toBe('application/json');
    expect(f.mock.calls[1][1].body).toBe('{"a":1}');
  });

  it('sends no Authorization header when signed out', async () => {
    const f = reply(200, {});
    vi.stubGlobal('fetch', f);
    await api('GET', '/verify/x');
    expect(sent(f).headers.Authorization).toBeUndefined();
  });

  it('turns an error response into an ApiError carrying the server message', async () => {
    vi.stubGlobal('fetch', reply(409, { error: 'already exists' }));
    await expect(api('POST', '/users', {})).rejects.toMatchObject({ status: 409, message: 'already exists' });
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 502, json: async () => { throw new Error('html'); } }));
    const e = await api('GET', '/x').catch((x) => x);
    expect(e).toBeInstanceOf(ApiError);
    expect(e.message).toBe('request failed (502)');
  });

  it('signs the user out when a token is rejected, but not on a failed login', async () => {
    setSession({ token: 'tok', email: 'a@b.c', role: 'faculty' });
    vi.stubGlobal('fetch', reply(401, { error: 'invalid email or password' }));
    await expect(api('POST', '/auth/login', {})).rejects.toThrow('invalid email or password');
    expect(getSession()).not.toBeNull();
    await expect(api('GET', '/credentials')).rejects.toThrow();
    expect(getSession()).toBeNull();
    expect(sessionStorage.getItem('acvs.session')).toBeNull();
  });

  it('keeps the session in sessionStorage and announces changes', () => {
    const seen = vi.fn();
    window.addEventListener('session', seen);
    setSession({ token: 't', email: 'e@x.y', role: 'auditor' });
    expect(JSON.parse(sessionStorage.getItem('acvs.session')!)).toMatchObject({ token: 't', role: 'auditor' });
    expect(seen).toHaveBeenCalledTimes(1);
    window.removeEventListener('session', seen);
  });
});
