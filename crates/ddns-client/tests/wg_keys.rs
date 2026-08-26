//! WG key unit tests (plan Task 2).

use ddns_client::wg::keys::generate_keypair;

#[test]
fn keypair_roundtrip_and_distinctness() {
    let (sk1, pk1) = generate_keypair();
    let (sk2, pk2) = generate_keypair();
    assert_ne!(sk1.to_bytes(), sk2.to_bytes());
    assert_ne!(pk1.to_bytes(), pk2.to_bytes());
    assert_eq!(pk1.to_bytes().len(), 32);
    assert_eq!(sk1.public_key().to_bytes(), pk1.to_bytes());
}
