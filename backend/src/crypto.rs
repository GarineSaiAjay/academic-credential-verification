use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// serde_json maps are BTreeMaps (sorted keys, no whitespace), so serialization is canonical.
pub fn canonical_hash(value: &serde_json::Value) -> String {
    sha256_hex(
        serde_json::to_string(value)
            .expect("json value serializes")
            .as_bytes(),
    )
}

/// Bytes signed by each approver; binds credential, stage and content hash together.
pub fn approval_message(credential_id: Uuid, role: &str, credential_hash: &str) -> Vec<u8> {
    format!("ACVS-APPROVAL-v1|{credential_id}|{role}|{credential_hash}").into_bytes()
}

pub fn public_from_seed(seed: &[u8; 32]) -> String {
    hex::encode(SigningKey::from_bytes(seed).verifying_key().to_bytes())
}

pub fn new_keypair() -> ([u8; 32], String) {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let public = public_from_seed(&seed);
    (seed, public)
}

pub fn sign(seed: &[u8; 32], message: &[u8]) -> String {
    hex::encode(SigningKey::from_bytes(seed).sign(message).to_bytes())
}

/// Returns false for malformed keys/signatures instead of erroring.
pub fn verify(public_hex: &str, signature_hex: &str, message: &[u8]) -> bool {
    let Ok(pk) = hex::decode(public_hex).map(<[u8; 32]>::try_from) else {
        return false;
    };
    let Ok(pk) = pk else { return false };
    let Ok(sig) = hex::decode(signature_hex).map(<[u8; 64]>::try_from) else {
        return false;
    };
    let Ok(sig) = sig else { return false };
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else {
        return false;
    };
    vk.verify_strict(message, &Signature::from_bytes(&sig))
        .is_ok()
}

/// AES-256-GCM; output is nonce(12) || ciphertext.
pub fn seal(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(key.into());
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let mut out = nonce.to_vec();
    out.extend(
        cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .expect("aes-gcm encrypt"),
    );
    out
}

pub fn open(key: &[u8; 32], blob: &[u8]) -> Option<Vec<u8>> {
    if blob.len() < 28 {
        return None;
    }
    let (nonce, ct) = blob.split_at(12);
    Aes256Gcm::new(key.into())
        .decrypt(Nonce::from_slice(nonce), ct)
        .ok()
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Step {
    pub hash: String,
    pub left: bool,
}

/// Merkle tree with 0x00/0x01 domain separation; odd nodes are promoted (never duplicated).
pub mod merkle {
    use super::*;

    fn leaf(hash_hex: &str) -> Option<[u8; 32]> {
        let bytes = hex::decode(hash_hex).ok()?;
        let mut h = Sha256::new();
        h.update([0u8]);
        h.update(bytes);
        Some(h.finalize().into())
    }

    fn node(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update([1u8]);
        h.update(l);
        h.update(r);
        h.finalize().into()
    }

    fn levels(leaves: &[String]) -> Option<Vec<Vec<[u8; 32]>>> {
        let mut cur: Vec<[u8; 32]> = leaves.iter().map(|l| leaf(l)).collect::<Option<_>>()?;
        if cur.is_empty() {
            return None;
        }
        let mut all = vec![cur.clone()];
        while cur.len() > 1 {
            cur = cur
                .chunks(2)
                .map(|c| {
                    if c.len() == 2 {
                        node(&c[0], &c[1])
                    } else {
                        c[0]
                    }
                })
                .collect();
            all.push(cur.clone());
        }
        Some(all)
    }

    pub fn root(leaves: &[String]) -> Option<String> {
        levels(leaves).map(|l| hex::encode(l.last().unwrap()[0]))
    }

    pub fn proof(leaves: &[String], index: usize) -> Option<Vec<Step>> {
        let levels = levels(leaves)?;
        if index >= leaves.len() {
            return None;
        }
        let (mut idx, mut steps) = (index, vec![]);
        for level in &levels[..levels.len() - 1] {
            let sibling = idx ^ 1;
            if let Some(s) = level.get(sibling) {
                steps.push(Step {
                    hash: hex::encode(s),
                    left: idx % 2 == 1,
                });
            }
            idx /= 2;
        }
        Some(steps)
    }

    pub fn verify(leaf_hash: &str, steps: &[Step], root_hex: &str) -> bool {
        let Some(mut cur) = leaf(leaf_hash) else {
            return false;
        };
        for s in steps {
            let Ok(Ok(sib)) = hex::decode(&s.hash).map(<[u8; 32]>::try_from) else {
                return false;
            };
            cur = if s.left {
                node(&sib, &cur)
            } else {
                node(&cur, &sib)
            };
        }
        hex::encode(cur) == root_hex
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize) -> Vec<String> {
        (0..n)
            .map(|i| sha256_hex(format!("leaf-{i}").as_bytes()))
            .collect()
    }

    #[test]
    fn canonical_hash_ignores_key_order() {
        let a = serde_json::json!({"b": 1, "a": 2});
        let b = serde_json::json!({"a": 2, "b": 1});
        assert_eq!(canonical_hash(&a), canonical_hash(&b));
        assert_eq!(serde_json::to_string(&a).unwrap(), r#"{"a":2,"b":1}"#);
    }

    #[test]
    fn sign_verify_roundtrip_and_tamper() {
        let (seed, public) = new_keypair();
        let sig = sign(&seed, b"msg");
        assert!(verify(&public, &sig, b"msg"));
        assert!(!verify(&public, &sig, b"other"));
        assert!(!verify(&public, "zz", b"msg"));
        let (_, other) = new_keypair();
        assert!(!verify(&other, &sig, b"msg"));
    }

    #[test]
    fn seal_open_roundtrip() {
        let key = [7u8; 32];
        let blob = seal(&key, b"secret");
        assert_eq!(open(&key, &blob).unwrap(), b"secret");
        assert!(open(&[8u8; 32], &blob).is_none());
        let mut bad = blob.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(open(&key, &bad).is_none());
    }

    #[test]
    fn merkle_proofs_for_every_size() {
        for n in 1..=17 {
            let l = leaves(n);
            let root = merkle::root(&l).unwrap();
            for i in 0..n {
                let p = merkle::proof(&l, i).unwrap();
                assert!(merkle::verify(&l[i], &p, &root), "n={n} i={i}");
            }
            assert!(!merkle::verify(
                &sha256_hex(b"forged"),
                &merkle::proof(&l, 0).unwrap(),
                &root
            ));
        }
    }

    #[test]
    fn merkle_odd_tree_is_not_duplicate_ambiguous() {
        let l = leaves(3);
        let mut dup = l.clone();
        dup.push(l[2].clone());
        assert_ne!(merkle::root(&l), merkle::root(&dup));
    }
}
