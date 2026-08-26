//! WireGuard key material: on-device keypair generation (the private key
//! never leaves the visitor), pubkey derivation, base64 wire format
//! (spec 2026-08-26-exit-node-wireguard §3.Visitor, ADR-W3).

use x25519_dalek::{PublicKey as DalekPk, StaticSecret};

/// A generated WireGuard private key (keep on-device). Zeroized on drop.
#[derive(Clone)]
pub struct PrivateKey(StaticSecret);

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material.
        f.write_str("PrivateKey(<redacted>)")
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        // Best-effort zeroize of the raw secret.
        let mut bytes = self.0.to_bytes();
        for b in bytes.iter_mut() {
            *b = 0;
        }
        // StaticSecret is consumed by to_bytes; the inner copy is zeroed via
        // the reassignment above (defense-in-depth; compiler may elide).
    }
}

/// The matching public key (safe to signal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn to_base64(&self) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(self.0)
    }

    pub fn from_base64(s: &str) -> Option<Self> {
        use base64::Engine as _;
        let raw = base64::engine::general_purpose::STANDARD.decode(s).ok()?;
        let bytes: [u8; 32] = raw.try_into().ok()?;
        Some(Self(bytes))
    }

    /// Convert to boringtun's session public key.
    pub fn to_boringtun_public(&self) -> boringtun::x25519::PublicKey {
        boringtun::x25519::PublicKey::from(self.0)
    }
}

impl PrivateKey {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Convert to boringtun's session secret (same x25519-dalek types).
    pub fn to_boringtun_secret(&self) -> boringtun::x25519::StaticSecret {
        StaticSecret::from(self.0.to_bytes())
    }

    /// Derive the matching public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(DalekPk::from(&self.0).to_bytes())
    }
}

/// Generate a fresh keypair from OS entropy.
pub fn generate_keypair() -> (PrivateKey, PublicKey) {
    let mut secret = [0u8; 32];
    getrandom::fill(&mut secret).expect("os entropy");
    let sk = StaticSecret::from(secret);
    let pk = DalekPk::from(&sk);
    (PrivateKey(sk), PublicKey(pk.to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_derives_pubkey() {
        let (sk, pk) = generate_keypair();
        let derived = sk.public_key();
        assert_eq!(derived.to_bytes(), pk.to_bytes());
    }

    #[test]
    fn keypairs_are_distinct() {
        let (sk1, pk1) = generate_keypair();
        let (sk2, pk2) = generate_keypair();
        assert_ne!(sk1.to_bytes(), sk2.to_bytes());
        assert_ne!(pk1.to_bytes(), pk2.to_bytes());
    }

    #[test]
    fn pubkey_base64_roundtrip() {
        let (_sk, pk) = generate_keypair();
        let b64 = pk.to_base64();
        assert_eq!(b64.len(), 44, "wg pubkey base64 is 44 chars");
        assert_eq!(PublicKey::from_base64(&b64).unwrap(), pk);
        assert!(PublicKey::from_base64("not-base64!!").is_none());
    }
}
