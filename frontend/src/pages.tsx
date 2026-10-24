import { FormEvent, ReactNode, useCallback, useEffect, useState } from 'react';
import { api, ApiError, getSession, Role, setSession } from './api';
import { Challenge, registerKey, sign as signWithKey, webauthnSupported } from './webauthn';

export const go = (hash: string) => { window.location.hash = hash; };

function useLoad<T>(path: string | null) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState('');
  const [tick, setTick] = useState(0);
  useEffect(() => {
    if (!path) return;
    let live = true;
    setError('');
    api<T>('GET', path).then((d) => live && setData(d)).catch((e: ApiError) => live && setError(e.message));
    return () => { live = false; };
  }, [path, tick]);
  return { data, error, reload: useCallback(() => setTick((t) => t + 1), []) };
}

function useAction() {
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const run = async (fn: () => Promise<unknown>, okText: string, after?: () => void) => {
    try { await fn(); setMsg({ ok: true, text: okText }); after?.(); }
    catch (e) { setMsg({ ok: false, text: (e as Error).message }); }
  };
  const banner = msg && <div className={msg.ok ? 'notice ok' : 'notice err'}>{msg.text}</div>;
  return { run, banner };
}

const Verdict = ({ v }: { v: string }) => <span className={`verdict v-${v.toLowerCase()}`}>{v}</span>;
const Status = ({ s }: { s: string }) => <span className={`status s-${s}`}>{s.replace(/_/g, ' ')}</span>;
const short = (s: string, n = 8) => s.slice(0, n);
const when = (s: string | number) => new Date(typeof s === 'number' ? s * 1000 : s).toLocaleString();
const Err = ({ msg }: { msg: string }) => (msg ? <div className="notice err">{msg}</div> : null);
const Card = ({ title, children }: { title: string; children: ReactNode }) => (
  <div className="box"><div className="box-title">{title}</div><div className="box-body">{children}</div></div>
);

export function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [mfaToken, setMfaToken] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  type LoginResult = { token?: string; email: string; role: Role; mfa_required?: boolean; mfa_token?: string; mfa_setup_required?: boolean };
  const done = (r: LoginResult) => {
    setSession({ token: r.token!, email: r.email, role: r.role, mfaSetup: !!r.mfa_setup_required });
    go(r.mfa_setup_required ? '/account' : '/');
  };
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true); setError('');
    try {
      if (mfaToken) {
        done(await api<LoginResult>('POST', '/auth/login/mfa', { mfa_token: mfaToken, code: code.trim() }));
      } else {
        const r = await api<LoginResult>('POST', '/auth/login', { email, password });
        if (r.mfa_required) { setMfaToken(r.mfa_token!); setPassword(''); } else done(r);
      }
    } catch (err) {
      setError((err as Error).message);
      // The interim sign-in lasts five minutes; once it is gone the password has to be entered again.
      if (mfaToken && err instanceof ApiError && err.status === 401 && /expired/.test(err.message)) { setMfaToken(''); setCode(''); }
    }
    setBusy(false);
  };
  return (
    <Card title="Sign in">
      <Err msg={error} />
      <form onSubmit={submit} className="form">
        {mfaToken ? (
          <>
            <p className="muted">Enter the 6-digit code from your authenticator app, or one of your recovery codes.</p>
            <label>Code<input value={code} onChange={(e) => setCode(e.target.value)} required autoFocus autoComplete="one-time-code" inputMode="text" /></label>
            <button disabled={busy}>{busy ? 'Checking...' : 'Sign in'}</button>{' '}
            <button type="button" className="small" onClick={() => { setMfaToken(''); setCode(''); setError(''); }}>Back</button>
          </>
        ) : (
          <>
            <label>Email<input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required autoFocus /></label>
            <label>Password<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required /></label>
            <button disabled={busy}>{busy ? 'Signing in...' : 'Sign in'}</button>
          </>
        )}
      </form>
      <p className="muted">Forgot your password? Ask a university administrator for a one-time reset link.</p>
      <p className="muted">Verifying a credential does not need an account: <a href="#/verify">verify by ID</a>.</p>
    </Card>
  );
}

export function ResetPassword({ token }: { token: string }) {
  const [pw, setPw] = useState('');
  const [again, setAgain] = useState('');
  const [busy, setBusy] = useState(false);
  const [doneFor, setDoneFor] = useState('');
  const { run, banner } = useAction();
  if (doneFor) return <Card title="Password changed"><p>The password for {doneFor} was changed and every session was signed out. <a href="#/login">Sign in</a>.</p></Card>;
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (pw !== again) { await run(() => Promise.reject(new Error('the two passwords differ')), ''); return; }
    setBusy(true);
    await run(async () => { const r = await api<{ email: string }>('POST', '/auth/reset-password', { token, new_password: pw }); setDoneFor(r.email); }, '');
    setBusy(false);
  };
  return (
    <Card title="Choose a new password">
      {banner}
      {!token && <div className="notice err">This page needs the link an administrator gave you.</div>}
      <form onSubmit={submit} className="form">
        <label>New password (12-128 characters)<input type="password" value={pw} onChange={(e) => setPw(e.target.value)} minLength={12} maxLength={128} required autoComplete="new-password" autoFocus /></label>
        <label>Again<input type="password" value={again} onChange={(e) => setAgain(e.target.value)} required autoComplete="new-password" /></label>
        <button disabled={busy || !token}>{busy ? 'Saving...' : 'Set password'}</button>
      </form>
      <p className="muted">If you use an authenticator app, you will still need your code to sign in.</p>
    </Card>
  );
}

interface Row { id: string; student_id: string; student_name: string; program: string; status: string; created_at: string }

const QUEUE: Partial<Record<Role, string>> = { exam_cell: 'pending_exam_cell', registrar: 'pending_registrar', university_admin: 'pending_university' };
const STATUSES = ['', 'pending_exam_cell', 'pending_registrar', 'pending_university', 'issued', 'rejected', 'revoked'];

export function CredList({ role }: { role: Role }) {
  const [status, setStatus] = useState(QUEUE[role] ?? '');
  const { data, error } = useLoad<{ credentials: Row[] }>(`/credentials${status ? `?status=${status}` : ''}`);
  return (
    <Card title={role === 'faculty' ? 'My credentials' : 'Credentials'}>
      <Err msg={error} />
      <div className="toolbar">
        <label>Status{' '}
          <select value={status} onChange={(e) => setStatus(e.target.value)}>
            {STATUSES.map((s) => <option key={s} value={s}>{s ? s.replace(/_/g, ' ') : 'all'}</option>)}
          </select>
        </label>
        {role === 'faculty' && <a className="btn" href="#/new">New credential</a>}
      </div>
      <table>
        <thead><tr><th>ID</th><th>Student</th><th>Program</th><th>Status</th><th>Created</th></tr></thead>
        <tbody>
          {data?.credentials.map((c) => (
            <tr key={c.id}>
              <td><a href={`#/c/${c.id}`}>{short(c.id)}</a></td>
              <td>{c.student_name} <span className="muted">({c.student_id})</span></td>
              <td>{c.program}</td>
              <td><Status s={c.status} /></td>
              <td>{when(c.created_at)}</td>
            </tr>
          ))}
          {data && data.credentials.length === 0 && <tr><td colSpan={5} className="muted">Nothing here.</td></tr>}
        </tbody>
      </table>
    </Card>
  );
}

export function NewCredential() {
  const [f, setF] = useState({ student_id: '', student_name: '', program: '', graduation_date: '', gpa: '', honors: '' });
  const { run, banner } = useAction();
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    run(async () => { const r = await api<{ id: string }>('POST', '/credentials', f); go(`/c/${r.id}`); }, 'Created');
  };
  return (
    <Card title="New credential">
      {banner}
      <form onSubmit={submit} className="form">
        <label>Student ID<input value={f.student_id} onChange={set('student_id')} required maxLength={64} /></label>
        <label>Student name<input value={f.student_name} onChange={set('student_name')} required maxLength={200} /></label>
        <label>Program<input value={f.program} onChange={set('program')} required maxLength={200} /></label>
        <label>Graduation date<input type="date" value={f.graduation_date} onChange={set('graduation_date')} required /></label>
        <label>GPA (optional)<input value={f.gpa} onChange={set('gpa')} maxLength={10} /></label>
        <label>Honors (optional)<input value={f.honors} onChange={set('honors')} maxLength={100} /></label>
        <button>Create and sign as faculty</button>
      </form>
    </Card>
  );
}

interface Sig { role: string; valid: boolean; key_status: string; public_key: string; signed_at: string; personal?: { valid: boolean; fingerprint: string; key_status: string } | null }

function SigTable({ sigs }: { sigs: Sig[] }) {
  return (
    <table>
      <thead><tr><th>Stage</th><th>Signature</th><th>Key</th><th>Public key</th><th>Personal signature</th><th>Signed</th></tr></thead>
      <tbody>
        {sigs.map((s) => (
          <tr key={s.role}>
            <td>{s.role.replace('_', ' ')}</td>
            <td className={s.valid ? 'good' : 'bad'}>{s.valid ? 'valid' : 'INVALID'}</td>
            <td className={s.key_status === 'revoked' ? 'bad' : ''}>{s.key_status}</td>
            <td className="mono">{short(s.public_key, 16)}…</td>
            <td className={s.personal ? (s.personal.valid ? 'good' : 'bad') : 'muted'}>{s.personal ? (s.personal.valid ? `valid (key ${s.personal.fingerprint.slice(0, 8)})` : `INVALID (${s.personal.key_status} key ${s.personal.fingerprint.slice(0, 8)})`) : 'none'}</td>
            <td>{when(s.signed_at)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

const NEXT: Record<string, Role> = { pending_exam_cell: 'exam_cell', pending_registrar: 'registrar', pending_university: 'university_admin' };

export function CredDetail({ id, role }: { id: string; role: Role }) {
  const { data: c, error, reload } = useLoad<any>(`/credentials/${id}`);
  const { run, banner } = useAction();
  const reason = (label: string) => window.prompt(label)?.trim() || null;
  const canSign = c && NEXT[c.status] === role;
  // What this person's security key would be asked to sign here, if anything.
  const [pc, setPc] = useState<Challenge | null>(null);
  useEffect(() => {
    api<Challenge>('GET', `/credentials/${id}/personal-challenge`).then(setPc).catch(() => setPc(null));
  }, [id, c?.status, c?.signatures?.length, c?.signatures?.filter((x: any) => x.personal).length]);
  const approve = async () => {
    if (pc && pc.purpose === 'approve' && pc.allow.length > 0) return api('POST', `/credentials/${id}/approve`, { webauthn: await signWithKey(pc) });
    if (pc?.required) throw new Error('This site requires your personal security-key signature. Add a key on your Account page first.');
    return api('POST', `/credentials/${id}/approve`);
  };
  const countersign = async () => api('POST', `/credentials/${id}/countersign`, { webauthn: await signWithKey(pc as Challenge) });
  return (
    <div>
      {banner}<Err msg={error} />
      {c && (
        <>
          <Card title={`Credential ${short(c.id)}`}>
            <table className="kv"><tbody>
              <tr><th>Verdict</th><td><Verdict v={c.verdict} /> <Status s={c.status} /></td></tr>
              <tr><th>Student</th><td>{c.student_name} ({c.student_id})</td></tr>
              <tr><th>Program</th><td>{c.program}</td></tr>
              <tr><th>Graduation</th><td>{c.graduation_date}</td></tr>
              <tr><th>GPA / Honors</th><td>{c.gpa ?? '-'} / {c.honors ?? '-'}</td></tr>
              <tr><th>Content hash</th><td className="mono">{c.credential_hash}</td></tr>
              <tr><th>Anchored</th><td>{c.block_height ? `block #${c.block_height}, leaf ${c.leaf_index}` : 'not yet'}</td></tr>
              {c.revoke_reason && <tr><th>Reason</th><td>{c.revoke_reason}</td></tr>}
              {c.supersedes && <tr><th>Replaces</th><td><a href={`#/c/${c.supersedes}`}>{short(c.supersedes)}</a></td></tr>}
              {c.superseded_by && <tr><th>Replaced by</th><td><a href={`#/c/${c.superseded_by.id}`}>{short(c.superseded_by.id)}</a> <Verdict v={c.superseded_by.verdict} /></td></tr>}
              {c.termination && <tr><th>Signed {c.termination.kind}</th><td className={c.termination.valid ? 'good' : 'bad'}>{c.termination.valid ? `signature valid (${c.termination.stage.replace('_', ' ')} key${c.termination.legacy ? ', added later for an older record' : ''})` : 'SIGNATURE INVALID'}</td></tr>}
            </tbody></table>
            <div className="toolbar">
              {canSign && <button onClick={() => run(approve, 'Signed', reload)}>Sign as {role.replace('_', ' ')}{pc?.purpose === 'approve' && pc.allow.length > 0 ? ' with my security key' : ''}</button>}
              {pc?.purpose === 'countersign' && <button onClick={() => run(countersign, 'Personal signature added', reload)}>Add my personal signature ({pc.stage.replace('_', ' ')})</button>}
              {canSign && <button className="danger" onClick={() => { const r = reason('Reason for rejection'); r && run(() => api('POST', `/credentials/${id}/reject`, { reason: r }), 'Rejected', reload); }}>Reject</button>}
              {role === 'faculty' && ['REVOKED', 'REJECTED', 'INVALID'].includes(c.verdict) && (!c.superseded_by || ['rejected', 'revoked'].includes(c.superseded_by.status)) && <button onClick={() => window.confirm('Create a new credential from this one? It goes through every approval stage again.') && run(() => api<{ id: string }>('POST', `/credentials/${id}/reissue`, {}).then((r) => go(`/c/${r.id}`)), 'Re-issued')}>Re-issue</button>}
              {role === 'university_admin' && c.status === 'issued' && <button className="danger" onClick={() => { const r = reason('Reason for revocation'); r && run(() => api('POST', `/credentials/${id}/revoke`, { reason: r }), 'Revoked', reload); }}>Revoke</button>}
              <a className="btn" href={`#/verify/${id}/${short(c.credential_hash, 16)}`}>Public verification page</a>
            </div>
          </Card>
          <Card title="Signatures"><SigTable sigs={c.signatures} /></Card>
          <Card title="QR code"><img className="qr" alt="Verification QR code" src={`/api/v1/credentials/${id}/qr`} /></Card>
        </>
      )}
    </div>
  );
}

export function Verify({ id, h }: { id?: string; h?: string }) {
  const [input, setInput] = useState('');
  const { data: v, error } = useLoad<any>(id ? `/verify/${id}${h ? `?h=${h}` : ''}` : null);
  if (!id) {
    return (
      <Card title="Verify a credential">
        <form className="form" onSubmit={(e) => { e.preventDefault(); go(`/verify/${input.trim()}`); }}>
          <label>Credential ID<input value={input} onChange={(e) => setInput(e.target.value)} placeholder="uuid, or scan the QR code" required /></label>
          <button>Verify</button>
        </form>
      </Card>
    );
  }
  return (
    <div>
      <Err msg={error} />
      {v && (
        <>
          <Card title="Verification result">
            <p><Verdict v={v.verdict} /></p>
            {v.superseded_by && <div className={v.superseded_by.verdict === 'VALID' ? 'notice ok' : 'notice err'}>This credential was replaced by <a href={`#/verify/${v.superseded_by.id}`}>{short(v.superseded_by.id)}</a>, which currently reads {v.superseded_by.verdict}.</div>}
            {v.supersedes && <div className="notice ok">This credential replaces <a href={`#/verify/${v.supersedes}`}>{short(v.supersedes)}</a>.</div>}
            {v.qr_hash_match === false && <div className="notice err">The QR code does not match this credential's current content hash. Treat the printout as forged.</div>}
            <table className="kv"><tbody>
              <tr><th>Student</th><td>{v.credential.student_name}</td></tr>
              <tr><th>Program</th><td>{v.credential.program}</td></tr>
              <tr><th>Graduation</th><td>{v.credential.graduation_date}</td></tr>
              <tr><th>GPA / Honors</th><td>{v.credential.gpa ?? '-'} / {v.credential.honors ?? '-'}</td></tr>
              <tr><th>Content hash</th><td className="mono">{v.credential.credential_hash}</td></tr>
              {v.credential.revoke_reason && <tr><th>Reason</th><td>{v.credential.revoke_reason}</td></tr>}
              {v.termination && <tr><th>Signed {v.termination.kind}</th><td className={v.termination.valid ? 'good' : 'bad'}>{v.termination.valid ? `signature valid (${v.termination.stage.replace('_', ' ')} key${v.termination.legacy ? ', added later for an older record' : ''})` : 'SIGNATURE INVALID'}</td></tr>}
            </tbody></table>
          </Card>
          <Card title="Checks">
            <table className="kv"><tbody>
              {Object.entries(v.checks).map(([k, ok]) => <tr key={k}><th>{k.replace(/_/g, ' ')}</th><td className={ok ? 'good' : 'bad'}>{ok ? 'pass' : 'FAIL'}</td></tr>)}
              <tr><th>ledger anchor</th><td className={v.anchor ? (v.anchor.ok ? 'good' : 'bad') : 'muted'}>{v.anchor ? (v.anchor.ok ? 'pass' : 'FAIL') : 'not yet anchored'}</td></tr>
            </tbody></table>
          </Card>
          <Card title="Signatures"><SigTable sigs={v.signatures} /></Card>
          {v.anchor && (
            <Card title="Ledger anchor">
              <table className="kv"><tbody>
                <tr><th>Block</th><td>#{v.anchor.height} ({when(v.anchor.timestamp)})</td></tr>
                <tr><th>Block hash</th><td className="mono">{v.anchor.block_hash}</td></tr>
                <tr><th>Merkle root</th><td className="mono">{v.anchor.merkle_root}</td></tr>
                <tr><th>Proof</th><td>{v.anchor.proof.length} step(s), leaf index {v.anchor.leaf_index}</td></tr>
                <tr>
                  <th>External timestamp</th>
                  {v.anchor.external_timestamp ? (
                    <td className={v.anchor.external_timestamp.imprint_ok ? 'good' : 'bad'}>
                      {v.anchor.external_timestamp.imprint_ok ? `signed ${when(v.anchor.external_timestamp.time)} by ${v.anchor.external_timestamp.tsa}` : 'MISMATCH: the timestamp is not for this block'}
                      {' '}<a href={`/api/v1/ledger/blocks/${v.anchor.height}/timestamp.tsr`}>token</a>
                    </td>
                  ) : <td className="muted">not yet timestamped by an outside authority</td>}
                </tr>
              </tbody></table>
            </Card>
          )}
        </>
      )}
    </div>
  );
}

export function Keys({ role }: { role: Role }) {
  const { data, error, reload } = useLoad<{ keys: any[] }>('/keys');
  const { run, banner } = useAction();
  const admin = role === 'university_admin';
  return (
    <Card title="Signing keys">
      {banner}<Err msg={error} />
      {admin && (
        <div className="toolbar">
          {['faculty', 'exam_cell', 'registrar', 'university'].map((r) => (
            <button key={r} onClick={() => window.confirm(`Rotate the ${r} key?`) && run(() => api('POST', `/keys/${r}/rotate`), `${r} key rotated`, reload)}>Rotate {r.replace('_', ' ')}</button>
          ))}
        </div>
      )}
      <table>
        <thead><tr><th>Stage</th><th>Status</th><th>Public key</th><th>Signatures</th><th>Created</th><th /></tr></thead>
        <tbody>
          {data?.keys.map((k) => (
            <tr key={k.id}>
              <td>{k.role.replace('_', ' ')}</td>
              <td className={k.status === 'revoked' ? 'bad' : k.status === 'active' ? 'good' : 'muted'}>{k.status}{k.revoke_reason ? ` (${k.revoke_reason})` : ''}</td>
              <td className="mono">{short(k.public_key, 16)}…</td>
              <td>{k.signatures}</td>
              <td>{when(k.created_at)}</td>
              <td>{admin && k.status !== 'revoked' && <button className="danger small" onClick={() => { const r = window.prompt('Reason for revocation (credentials signed by this key become INVALID)')?.trim(); r && run(() => api('POST', `/keys/${k.id}/revoke`, { reason: r }), 'Key revoked', reload); }}>Revoke</button>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}

export function Ledger({ role }: { role: Role }) {
  const { data, error, reload } = useLoad<any>('/ledger/blocks');
  const [chain, setChain] = useState<any>(null);
  const { run, banner } = useAction();
  return (
    <Card title="Ledger">
      {banner}<Err msg={error} />
      <div className="toolbar">
        {role === 'university_admin' && <button onClick={() => run(() => api('POST', '/ledger/seal'), 'Block sealed', reload)}>Seal {data ? data.pending_unanchored : ''} issued credential(s) into a block</button>}
        {role === 'university_admin' && data?.timestamping && <button onClick={() => run(async () => { const r = await api<{ stamped: number; failed: { height: number; error: string }[] }>('POST', '/ledger/timestamp'); if (r.failed.length) throw new Error(`Block ${r.failed[0].height}: ${r.failed[0].error}`); return r; }, 'Pending blocks timestamped', reload)}>Timestamp pending blocks now</button>}
        <button onClick={() => api('GET', '/ledger/verify').then(setChain)}>Verify whole chain</button>
        {chain && <span className={chain.ok ? 'good' : 'bad'}>{chain.ok ? `chain intact (${chain.length} blocks)` : 'CHAIN BROKEN'}</span>}
      </div>
      <table>
        <thead><tr><th>#</th><th>Credentials</th><th>Merkle root</th><th>Block hash</th><th>Sealed</th>{data?.timestamping && <th>External timestamp</th>}</tr></thead>
        <tbody>
          {data?.blocks.map((b: any) => (
            <tr key={b.height}><td>{b.height}</td><td>{b.credentials}</td><td className="mono">{short(b.merkle_root, 16)}…</td><td className="mono">{short(b.block_hash, 16)}…</td><td>{when(b.timestamp)}</td>{data.timestamping && <td>{b.external_timestamp ? <a href={`#/ledger`} onClick={(e) => { e.preventDefault(); api('GET', `/ledger/blocks/${b.height}/timestamp`).then((t) => window.alert(`${t.verified ? 'Verified' : 'NOT VERIFIED'}\nsigned ${when(t.time)} by ${t.tsa}\nserial ${t.serial}${t.error ? `\n${t.error}` : ''}`)); }}>{when(b.external_timestamp.time)}</a> : <span className="muted">pending</span>}</td>}</tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}

export function Audit() {
  const { data, error } = useLoad<{ logs: any[] }>('/audit?limit=200');
  return (
    <Card title="Audit log">
      <Err msg={error} />
      <table>
        <thead><tr><th>#</th><th>Time</th><th>Actor</th><th>Action</th><th>Resource</th><th>Details</th></tr></thead>
        <tbody>
          {data?.logs.map((l) => (
            <tr key={l.id}>
              <td>{l.id}</td><td>{when(l.at)}</td><td>{l.actor ?? '-'}</td><td>{l.action}</td>
              <td className="mono">{l.resource_type ? `${l.resource_type}:${short(l.resource_id ?? '', 8)}` : '-'}</td>
              <td className="mono">{l.details ? JSON.stringify(l.details) : ''}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}

const ROLES: Role[] = ['faculty', 'exam_cell', 'registrar', 'university_admin', 'auditor'];
const roleName = (r: string) => r.replace('_', ' ');

export function Users({ me }: { me: string }) {
  const { data, error, reload } = useLoad<{ users: any[] }>('/users');
  const { run, banner } = useAction();
  const [form, setForm] = useState({ email: '', role: 'faculty', password: '' });
  const [busy, setBusy] = useState(false);
  const create = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    await run(() => api('POST', '/users', form), `Created ${form.email.trim().toLowerCase()}`, () => { setForm({ email: '', role: 'faculty', password: '' }); reload(); });
    setBusy(false);
  };
  return (
    <>
      <Card title="Users">
        {banner}<Err msg={error} />
        <table>
          <thead><tr><th>Email</th><th>Role</th><th>Status</th><th>2FA</th><th>Created</th><th /></tr></thead>
          <tbody>
            {data?.users.map((u) => {
              const self = u.email === me;
              return (
                <tr key={u.id}>
                  <td>{u.email}{self && <span className="muted"> (you)</span>}</td>
                  <td>
                    <select value={u.role} disabled={self} onChange={(e) => run(() => api('POST', `/users/${u.id}/role`, { role: e.target.value }), `${u.email} is now ${roleName(e.target.value)}`, reload)}>
                      {ROLES.map((r) => <option key={r} value={r}>{roleName(r)}</option>)}
                    </select>
                  </td>
                  <td className={u.active ? 'good' : 'bad'}>{u.active ? 'active' : 'deactivated'}</td>
                  <td className={u.two_factor ? 'good' : 'muted'}>{u.two_factor ? 'on' : 'off'}</td>
                  <td>{when(u.created_at)}</td>
                  <td>
                    {!self && (
                      <>
                        <button className="small" title="A one-time link, valid for an hour, that lets this person choose a new password" onClick={() => run(async () => { const r = await api<{ path: string }>('POST', `/users/${u.id}/reset-link`); window.prompt(`Give ${u.email} this link. It works once, for one hour. Copy it now; it is not shown again.`, `${window.location.origin}${r.path}`); }, `Reset link issued for ${u.email}`)}>Reset link</button>{' '}
                        <button className="small" onClick={() => window.confirm(`Sign ${u.email} out of every device?`) && run(() => api('POST', `/users/${u.id}/sessions/revoke`), `Signed out ${u.email} everywhere`)}>Sign out everywhere</button>{' '}
                        {u.two_factor && <><button className="small" title="For a lost phone: removes their second factor and signs them out" onClick={() => window.confirm(`Remove two-factor sign-in for ${u.email}? They are signed out everywhere.`) && run(() => api('POST', `/users/${u.id}/totp/reset`), `Two-factor sign-in removed for ${u.email}`, reload)}>Reset 2FA</button>{' '}</>}
                        <button className="small" title="Lets this person enrol a security key without an existing one, for 24 hours" onClick={() => window.confirm(`Allow ${u.email} to enrol a new security key for the next 24 hours?`) && run(() => api('POST', `/users/${u.id}/keys/enroll`), `${u.email} may enrol a key`)}>Allow key enrolment</button>{' '}
                        <button className="small" onClick={() => { const p = window.prompt(`New password for ${u.email} (12-128 characters). They will be signed out everywhere.`); p && run(() => api('POST', `/users/${u.id}/password`, { password: p }), `Password reset for ${u.email}`, reload); }}>Reset password</button>{' '}
                        <button className={u.active ? 'danger small' : 'small'} onClick={() => (!u.active || window.confirm(`Deactivate ${u.email}? They are signed out immediately.`)) && run(() => api('POST', `/users/${u.id}/active`, { active: !u.active }), `${u.email} ${u.active ? 'deactivated' : 'activated'}`, reload)}>{u.active ? 'Deactivate' : 'Activate'}</button>
                      </>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </Card>
      <Card title="Create user">
        <form onSubmit={create} className="form">
          <label>Email<input type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} required /></label>
          <label>Role
            <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
              {ROLES.map((r) => <option key={r} value={r}>{roleName(r)}</option>)}
            </select>
          </label>
          <label>Initial password (12-128 characters)<input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} minLength={12} maxLength={128} required autoComplete="new-password" /></label>
          <button disabled={busy}>{busy ? 'Creating...' : 'Create user'}</button>
        </form>
      </Card>
    </>
  );
}

function MyKeys() {
  const { data, error, reload } = useLoad<{ keys: any[] }>('/me/keys');
  const { run, banner } = useAction();
  const [label, setLabel] = useState('');
  return (
    <Card title="My security keys">
      {banner}<Err msg={error} />
      <p className="muted">A security key or passkey lets you sign approvals personally. Its private half never leaves your device, so nobody, including this server, can sign as you.</p>
      <table>
        <thead><tr><th>Name</th><th>Status</th><th>Fingerprint</th><th>Added</th><th /></tr></thead>
        <tbody>
          {data?.keys.map((k) => (
            <tr key={k.id}>
              <td>{k.label}</td>
              <td className={k.status === 'active' ? 'good' : k.status === 'revoked' ? 'bad' : 'muted'}>{k.status}{k.end_reason ? ` (${k.end_reason})` : ''}</td>
              <td className="mono">{k.fingerprint}</td>
              <td>{when(k.created_at)}</td>
              <td>
                {k.status === 'active' && <button className="small" onClick={() => window.confirm('Retire this key? It can no longer sign; what it signed stays valid.') && run(() => api('POST', `/user-keys/${k.id}/retire`), 'Key retired', reload)}>Retire</button>}{' '}
                {k.status !== 'revoked' && <button className="danger small" onClick={() => { const r = window.prompt('Why is this key compromised? Everything it signed will stop verifying.')?.trim(); r && run(() => api('POST', `/user-keys/${k.id}/revoke`, { reason: r }), 'Key revoked', reload); }}>Report compromised</button>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {webauthnSupported() ? (
        <form className="form" onSubmit={(e) => { e.preventDefault(); run(() => registerKey(label.trim()), 'Key added', () => { setLabel(''); reload(); }); }}>
          <label>Name for the new key (for example "YubiKey" or "laptop")<input value={label} onChange={(e) => setLabel(e.target.value)} maxLength={80} required /></label>
          <button>Add a security key / passkey</button>
        </form>
      ) : <p className="muted">This browser or connection cannot use security keys. Open the site over HTTPS in a current browser.</p>}
    </Card>
  );
}

function TwoFactor({ setupRequired }: { setupRequired: boolean }) {
  const { data, error, reload } = useLoad<{ enabled: boolean; recovery_codes_left: number; required: boolean }>('/auth/totp');
  const { run, banner } = useAction();
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [setup, setSetup] = useState<{ secret: string; qr: string } | null>(null);
  const [codes, setCodes] = useState<string[] | null>(null);
  const reset = () => { setPassword(''); setCode(''); setSetup(null); };
  // Turning it on lifts the "set this up first" restriction from the session that did it.
  const unlock = () => { const s = getSession(); if (s?.mfaSetup) setSession({ ...s, mfaSetup: false }); };
  return (
    <Card title="Two-factor sign-in">
      {banner}<Err msg={error} />
      {setupRequired && <div className="notice err">Your role must sign in with a second factor. Set it up below to continue.</div>}
      {data && !data.enabled && !setup && (
        <form className="form" onSubmit={(e) => { e.preventDefault(); run(async () => setSetup(await api('POST', '/auth/totp/setup', { password })), 'Scan the code with your authenticator app, then enter a code it shows.'); }}>
          <p className="muted">Adds a 6-digit code from an authenticator app (Google Authenticator, Authy, 1Password, ...) to signing in.</p>
          <label>Your password<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required autoComplete="current-password" /></label>
          <button>Set up</button>
        </form>
      )}
      {setup && (
        <form className="form" onSubmit={(e) => { e.preventDefault(); run(async () => { const r = await api<{ recovery_codes: string[] }>('POST', '/auth/totp/enable', { code }); setCodes(r.recovery_codes); unlock(); reset(); reload(); }, 'Two-factor sign-in is on. Your other sessions were signed out.'); }}>
          <img src={setup.qr} alt="QR code for your authenticator app" width={200} height={200} />
          <p className="muted">Cannot scan it? Enter this key in the app: <span className="mono">{setup.secret}</span></p>
          <label>Code from the app<input value={code} onChange={(e) => setCode(e.target.value)} required inputMode="numeric" autoComplete="one-time-code" /></label>
          <button>Turn on</button>{' '}<button type="button" className="small" onClick={reset}>Cancel</button>
        </form>
      )}
      {codes && (
        <div className="notice ok">
          <strong>Recovery codes.</strong> Each works once if you lose your phone. They are shown only now: save them somewhere safe.
          <pre className="mono">{codes.join('\n')}</pre>
          <button className="small" onClick={() => setCodes(null)}>I have saved them</button>
        </div>
      )}
      {data?.enabled && !setup && (
        <>
          <p>Two-factor sign-in is <span className="good">on</span>. {data.recovery_codes_left} recovery code(s) left.</p>
          <form className="form" onSubmit={(e) => e.preventDefault()}>
            <label>Your password<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" /></label>
            <label>A current code (or a recovery code)<input value={code} onChange={(e) => setCode(e.target.value)} autoComplete="one-time-code" /></label>
            <div>
              <button type="button" className="small" onClick={() => run(async () => { const r = await api<{ recovery_codes: string[] }>('POST', '/auth/totp/recovery-codes', { password, code }); setCodes(r.recovery_codes); setPassword(''); setCode(''); reload(); }, 'New recovery codes issued; the old ones no longer work.')}>New recovery codes</button>{' '}
              {data.required
                ? <span className="muted">Your role requires it, so it cannot be turned off here. If you lose your device, ask an administrator to reset it.</span>
                : <button type="button" className="danger small" onClick={() => window.confirm('Turn off two-factor sign-in?') && run(() => api('POST', '/auth/totp/disable', { password, code }), 'Two-factor sign-in is off.', () => { reset(); reload(); })}>Turn off</button>}
            </div>
          </form>
        </>
      )}
    </Card>
  );
}

function Sessions() {
  const { data, error, reload } = useLoad<{ sessions: { id: string; created_at: string; expires_at: string; ip: string | null; user_agent: string | null; current: boolean }[] }>('/auth/sessions');
  const { run, banner } = useAction();
  const others = (data?.sessions.length ?? 0) > 1;
  return (
    <Card title="Where you are signed in">
      {banner}<Err msg={error} />
      <table>
        <thead><tr><th>Device</th><th>Address</th><th>Signed in</th><th>Expires</th><th /></tr></thead>
        <tbody>
          {data?.sessions.map((x) => (
            <tr key={x.id}>
              <td>{x.user_agent || 'unknown'}{x.current && <span className="good"> (this one)</span>}</td>
              <td className="mono">{x.ip ?? ''}</td>
              <td>{when(x.created_at)}</td>
              <td>{when(x.expires_at)}</td>
              <td>{!x.current && <button className="small" onClick={() => run(() => api('POST', `/auth/sessions/${x.id}/revoke`), 'Session ended', reload)}>Sign out</button>}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {others && <p><button className="danger small" onClick={() => window.confirm('Sign out of every other device?') && run(() => api('POST', '/auth/sessions/revoke-others'), 'Signed out everywhere else', reload)}>Sign out everywhere else</button></p>}
    </Card>
  );
}

export function Account({ setupRequired = false }: { setupRequired?: boolean }) {
  const [form, setForm] = useState({ current_password: '', new_password: '' });
  const [busy, setBusy] = useState(false);
  const { run, banner } = useAction();
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    await run(() => api('POST', '/auth/password', form), 'Password changed. Your other sessions were signed out.', () => setForm({ current_password: '', new_password: '' }));
    setBusy(false);
  };
  return (
    <>
    <TwoFactor setupRequired={setupRequired} />
    {!setupRequired && <MyKeys />}
    {!setupRequired && <Sessions />}
    <Card title="Change password">
      {banner}
      <form onSubmit={submit} className="form">
        <label>Current password<input type="password" value={form.current_password} onChange={(e) => setForm({ ...form, current_password: e.target.value })} required autoComplete="current-password" /></label>
        <label>New password (12-128 characters)<input type="password" value={form.new_password} onChange={(e) => setForm({ ...form, new_password: e.target.value })} minLength={12} maxLength={128} required autoComplete="new-password" /></label>
        <button disabled={busy}>{busy ? 'Saving...' : 'Change password'}</button>
      </form>
    </Card>
    </>
  );
}

export async function logout() {
  if (getSession()) await api('POST', '/auth/logout').catch(() => undefined);
  setSession(null);
  go('/login');
}
