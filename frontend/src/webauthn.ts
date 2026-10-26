import { api } from './api';

const enc = (b: ArrayBuffer | Uint8Array): string => {
  const bytes = b instanceof Uint8Array ? b : new Uint8Array(b);
  let s = '';
  bytes.forEach((x) => { s += String.fromCharCode(x); });
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
const dec = (s: string): Uint8Array<ArrayBuffer> => {
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4));
  const out = new Uint8Array(new ArrayBuffer(bin.length));
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};

export const webauthnSupported = () => typeof window !== 'undefined' && !!window.PublicKeyCredential && !!navigator.credentials;

/** What the server asks the person's authenticator to sign next on a credential. */
export interface Challenge {
  purpose: 'approve' | 'countersign';
  stage: string;
  challenge: string;
  rp_id: string;
  allow: string[];
  required: boolean;
}

export interface Assertion { credential_id: string; authenticator_data: string; client_data_json: string; signature: string }

/** Registers a passkey / security key for the signed-in user. The private key stays in the authenticator. */
export async function registerKey(label: string): Promise<void> {
  if (!webauthnSupported()) throw new Error('This browser or connection does not support security keys (HTTPS is required).');
  const o = await api<any>('POST', '/me/keys/options');
  const cred = (await navigator.credentials.create({
    publicKey: {
      challenge: dec(o.challenge),
      rp: o.rp,
      user: { id: dec(o.user.id), name: o.user.name, displayName: o.user.display_name },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      excludeCredentials: o.exclude.map((id: string) => ({ type: 'public-key', id: dec(id) })),
      authenticatorSelection: { userVerification: 'required', residentKey: 'preferred' },
      attestation: 'none',
      timeout: o.timeout_ms,
    },
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error('No key was created.');
  const r = cred.response as AuthenticatorAttestationResponse;
  const publicKey = r.getPublicKey();
  if (!publicKey) throw new Error('This browser cannot export the public key; use a current browser.');
  // An account that already has a key must have that key approve the new one (so a stolen password alone
  // cannot add an attacker's key).
  let authorization: Assertion | undefined;
  if (o.authorize_allow.length > 0) {
    authorization = await assertion(o.challenge, o.rp.id, o.authorize_allow);
  }
  await api('POST', '/me/keys', {
    challenge_id: o.challenge_id,
    credential_id: enc(cred.rawId),
    public_key: enc(publicKey),
    client_data_json: enc(r.clientDataJSON),
    label,
    authorization,
  });
}

async function assertion(challenge: string, rpId: string, allow: string[]): Promise<Assertion> {
  const cred = (await navigator.credentials.get({
    publicKey: {
      challenge: dec(challenge),
      rpId,
      allowCredentials: allow.map((id) => ({ type: 'public-key' as const, id: dec(id) })),
      userVerification: 'required',
      timeout: 60000,
    },
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error('No signature was made.');
  const r = cred.response as AuthenticatorAssertionResponse;
  return {
    credential_id: enc(cred.rawId),
    authenticator_data: enc(r.authenticatorData),
    client_data_json: enc(r.clientDataJSON),
    signature: enc(r.signature),
  };
}

/** Asks the person's authenticator to sign the approval described by `ch`. */
export async function sign(ch: Challenge): Promise<Assertion> {
  if (!webauthnSupported()) throw new Error('This browser or connection does not support security keys (HTTPS is required).');
  if (ch.allow.length === 0) throw new Error('You have no security key registered. Add one on your Account page first.');
  return assertion(ch.challenge, ch.rp_id, ch.allow);
}
