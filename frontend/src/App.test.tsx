import { render, screen, act } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App';
import { Role, setSession } from './api';

beforeEach(() => {
  setSession(null);
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => ({ credentials: [], keys: [], users: [], blocks: [], logs: [] }) }));
});
afterEach(() => vi.unstubAllGlobals());

const as = (role: Role, extra = {}) => setSession({ token: 't', email: `${role}@u.edu`, role, ...extra });
const links = () => screen.getAllByRole('link').map((a) => a.textContent);

describe('navigation', () => {
  it('sends a signed-out visitor to the sign-in page', () => {
    render(<App />);
    expect(window.location.hash).toBe('#/login');
    expect(screen.getByRole('button', { name: 'Sign in' })).toBeInTheDocument();
  });

  it('lets anyone verify a credential without an account', () => {
    window.location.hash = '#/verify';
    render(<App />);
    expect(screen.getByText('Verify a credential')).toBeInTheDocument();
    expect(window.location.hash).toBe('#/verify');
  });

  it('shows each role only the pages it may use', () => {
    const expectations: Record<Role, { has: string[]; lacks: string[] }> = {
      faculty: { has: ['New', 'Credentials', 'Ledger'], lacks: ['Keys', 'Audit', 'Users'] },
      exam_cell: { has: ['Credentials', 'Ledger'], lacks: ['New', 'Keys', 'Audit', 'Users'] },
      registrar: { has: ['Credentials', 'Ledger'], lacks: ['New', 'Keys', 'Audit', 'Users'] },
      auditor: { has: ['Keys', 'Audit', 'Ledger'], lacks: ['New', 'Users'] },
      university_admin: { has: ['Keys', 'Audit', 'Users', 'Ledger'], lacks: ['New'] },
    };
    for (const [role, { has, lacks }] of Object.entries(expectations) as [Role, { has: string[]; lacks: string[] }][]) {
      as(role);
      const { unmount } = render(<App />);
      const names = links();
      for (const h of has) expect(names, `${role} sees ${h}`).toContain(h);
      for (const l of lacks) expect(names, `${role} must not see ${l}`).not.toContain(l);
      unmount();
    }
  });

  it('does not open the users page for anyone but an administrator', () => {
    as('auditor');
    window.location.hash = '#/users';
    render(<App />);
    expect(screen.queryByText('Users')).not.toBeInTheDocument();
    expect(screen.getByText('Credentials', { selector: '.box-title' })).toBeInTheDocument();
  });

  it('locks a session that still has to set up two-factor to the account page', () => {
    as('registrar', { mfaSetup: true });
    window.location.hash = '#/ledger';
    render(<App />);
    expect(links()).not.toContain('Ledger');
    expect(links()).not.toContain('Credentials');
    expect(screen.getByText(/two-factor/i, { selector: '.notice, .box-title, p, h2, div' })).toBeInTheDocument();
  });

  it('redraws when the session changes without the address changing', () => {
    as('registrar', { mfaSetup: true });
    render(<App />);
    expect(links()).not.toContain('Ledger');
    act(() => as('registrar'));
    expect(links()).toContain('Ledger');
  });

  it('signs out from the header', async () => {
    as('faculty');
    render(<App />);
    await act(async () => { screen.getByText('logout').click(); });
    expect(screen.getByRole('button', { name: 'Sign in' })).toBeInTheDocument();
  });
});
