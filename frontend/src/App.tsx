import { useEffect, useState } from 'react';
import { getSession } from './api';
import { Account, Audit, CredDetail, CredList, Keys, Ledger, Login, NewCredential, ResetPassword, Users, Verify, go, logout } from './pages';

function useHash() {
  const read = () => window.location.hash.replace(/^#/, '') || '/';
  const [path, setPath] = useState(read);
  const [, redraw] = useState(0);
  useEffect(() => {
    // The session can change (for example, a second factor gets set up) without the address changing.
    const on = () => { setPath(read()); redraw((n) => n + 1); };
    window.addEventListener('hashchange', on);
    window.addEventListener('session', on);
    return () => { window.removeEventListener('hashchange', on); window.removeEventListener('session', on); };
  }, []);
  return path;
}

export default function App() {
  const path = useHash();
  const session = getSession();
  const parts = path.split('/').filter(Boolean);

  // Public routes work without an account.
  const isPublic = parts[0] === 'verify' || parts[0] === 'login' || parts[0] === 'reset';
  useEffect(() => { if (!session && !isPublic) go('/login'); }, [session, isPublic]);

  let page;
  if (parts[0] === 'verify') page = <Verify id={parts[1]} h={parts[2]} />;
  else if (parts[0] === 'reset') page = <ResetPassword token={parts[1] ?? ''} />;
  else if (!session) page = <Login />;
  // A role that must use a second factor, and has none yet, may do nothing but set it up.
  else if (session.mfaSetup) page = <Account setupRequired />;
  else if (parts[0] === 'login') page = <Login />;
  else if (parts[0] === 'new') page = <NewCredential />;
  else if (parts[0] === 'c' && parts[1]) page = <CredDetail id={parts[1]} role={session.role} />;
  else if (parts[0] === 'keys') page = <Keys role={session.role} />;
  else if (parts[0] === 'ledger') page = <Ledger role={session.role} />;
  else if (parts[0] === 'audit') page = <Audit />;
  else if (parts[0] === 'users' && session.role === 'university_admin') page = <Users me={session.email} />;
  else if (parts[0] === 'account') page = <Account />;
  else page = <CredList role={session.role} />;

  const locked = !!session?.mfaSetup;
  const privileged = session?.role === 'university_admin' || session?.role === 'auditor';
  return (
    <>
      <header>
        <a className="brand" href="#/">ACVS</a>
        <nav>
          {session && !locked && <a href="#/">Credentials</a>}
          {!locked && session?.role === 'faculty' && <a href="#/new">New</a>}
          <a href="#/verify">Verify</a>
          {session && !locked && <a href="#/ledger">Ledger</a>}
          {privileged && !locked && <a href="#/keys">Keys</a>}
          {privileged && !locked && <a href="#/audit">Audit</a>}
          {!locked && session?.role === 'university_admin' && <a href="#/users">Users</a>}
        </nav>
        <span className="who">
          {session ? (<><a href="#/account">{session.email}</a> <span className="muted">({session.role.replace('_', ' ')})</span> · <a href="#/login" onClick={(e) => { e.preventDefault(); logout(); }}>logout</a></>) : <a href="#/login">login</a>}
        </span>
      </header>
      <main>{page}</main>
    </>
  );
}
