export type Role = 'faculty' | 'exam_cell' | 'registrar' | 'university_admin' | 'auditor';
export interface Session { token: string; email: string; role: Role }

const KEY = 'acvs.session';
let session: Session | null = null;
try { session = JSON.parse(sessionStorage.getItem(KEY) ?? 'null'); } catch { session = null; }

export const getSession = () => session;
export function setSession(s: Session | null) {
  session = s;
  try { s ? sessionStorage.setItem(KEY, JSON.stringify(s)) : sessionStorage.removeItem(KEY); } catch { /* storage unavailable */ }
  window.dispatchEvent(new Event('session'));
}

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

function nonce(): string {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

export async function api<T = any>(method: 'GET' | 'POST', path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (session) headers.Authorization = `Bearer ${session.token}`;
  if (method === 'POST') {
    headers['X-Nonce'] = nonce();
    headers['X-Timestamp'] = String(Math.floor(Date.now() / 1000));
  }
  const res = await fetch(`/api/v1${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    if (res.status === 401 && session && path !== '/auth/login') setSession(null);
    throw new ApiError(res.status, data.error ?? `request failed (${res.status})`);
  }
  return data as T;
}
