import { useEffect, useState } from 'react';
import { getSession } from './api';
import { Account, Audit, CredDetail, CredList, Keys, Ledger, Login, NewCredential, Users, Verify, go, logout } from './pages';

function useHash() {
  const read = () => window.location.hash.replace(/^#/, '') || '/';
  const [path, setPath] = useState(read);
  useEffect(() => {
    const on = () => setPath(read());
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
  const isPublic = parts[0] === 'verify' || parts[0] === 'login';
  useEffect(() => { if (!session && !isPublic) go('/login'); }, [session, isPublic]);

  let page;
  if (parts[0] === 'verify') page = <Verify id={parts[1]} h={parts[2]} />;
  else if (!session) page = <Login />;
  else if (parts[0] === 'login') page = <Login />;
  else if (parts[0] === 'new') page = <NewCredential />;
  else if (parts[0] === 'c' && parts[1]) page = <CredDetail id={parts[1]} role={session.role} />;
  else if (parts[0] === 'keys') page = <Keys role={session.role} />;
  else if (parts[0] === 'ledger') page = <Ledger role={session.role} />;
  else if (parts[0] === 'audit') page = <Audit />;
  else if (parts[0] === 'users' && session.role === 'university_admin') page = <Users me={session.email} />;
  else if (parts[0] === 'account') page = <Account />;
  else page = <CredList role={session.role} />;

  const privileged = session?.role === 'university_admin' || session?.role === 'auditor';
  return (
    <>
      <header>
        <a className="brand" href="#/">ACVS</a>
        <nav>
          {session && <a href="#/">Credentials</a>}
          {session?.role === 'faculty' && <a href="#/new">New</a>}
          <a href="#/verify">Verify</a>
          {session && <a href="#/ledger">Ledger</a>}
          {privileged && <a href="#/keys">Keys</a>}
          {privileged && <a href="#/audit">Audit</a>}
          {session?.role === 'university_admin' && <a href="#/users">Users</a>}
        </nav>
        <span className="who">
          {session ? (<><a href="#/account">{session.email}</a> <span className="muted">({session.role.replace('_', ' ')})</span> · <a href="#/login" onClick={(e) => { e.preventDefault(); logout(); }}>logout</a></>) : <a href="#/login">login</a>}
        </span>
      </header>
      <main>{page}</main>
    </>
  );
}
