//! identikey-auth-challenge-v1 fixtures: tests verify AGAINST committed bytes.

use identikey_auth::{
    verify_response, Challenge, InMemoryNonceStore, NonceStore, Response, Signer, SoftwareSigner,
    VERSION, VerifyPolicy,
};

const AUD: &str = "identikey-vector";
const NOW: u64 = 1_700_000_000;
const TTL: u64 = 120;
const SKEW: u64 = 30;

fn challenge_fixture() -> Challenge {
    Challenge {
        version: VERSION,
        audience: AUD.to_string(),
        nonce: vec![0x42u8; 16],
        issued_at: NOW,
        expires_at: NOW + TTL,
    }
}

fn store_with(chal: &Challenge) -> InMemoryNonceStore {
    let mut s = InMemoryNonceStore::new();
    s.record_issued(&chal.nonce, chal.expires_at);
    s
}

#[test]
fn ed25519_fixture_verifies() {
    let chal = challenge_fixture();
    let bytes = include_bytes!("fixtures/response-ed25519.bin");
    let resp = Response::from_bytes(bytes).unwrap();
    assert_eq!(resp.challenge_bytes, chal.to_bytes());
    let mut store = store_with(&chal);
    verify_response(&resp, AUD, NOW, SKEW, VerifyPolicy::PqOptional, &mut store).unwrap();
    // Replay
    assert!(
        verify_response(&resp, AUD, NOW, SKEW, VerifyPolicy::PqOptional, &mut store).is_err()
    );
}

#[test]
fn p256_fixture_verifies() {
    let chal = challenge_fixture();
    let bytes = include_bytes!("fixtures/response-p256.bin");
    let resp = Response::from_bytes(bytes).unwrap();
    let mut store = store_with(&chal);
    verify_response(&resp, AUD, NOW, SKEW, VerifyPolicy::PqOptional, &mut store).unwrap();
}

#[test]
fn fixture_audience_mismatch() {
    let bytes = include_bytes!("fixtures/response-ed25519.bin");
    let resp = Response::from_bytes(bytes).unwrap();
    let mut store = store_with(&challenge_fixture());
    assert!(
        verify_response(&resp, "other-aud", NOW, SKEW, VerifyPolicy::PqOptional, &mut store)
            .is_err()
    );
}

#[test]
fn fixture_expiry() {
    let bytes = include_bytes!("fixtures/response-ed25519.bin");
    let resp = Response::from_bytes(bytes).unwrap();
    let mut store = store_with(&challenge_fixture());
    assert!(
        verify_response(&resp, AUD, NOW + 10_000, SKEW, VerifyPolicy::PqOptional, &mut store)
            .is_err()
    );
}

#[test]
fn fixture_pq_required_rejects_classical() {
    let bytes = include_bytes!("fixtures/response-ed25519.bin");
    let resp = Response::from_bytes(bytes).unwrap();
    let mut store = store_with(&challenge_fixture());
    assert!(
        verify_response(&resp, AUD, NOW, SKEW, VerifyPolicy::PqRequired, &mut store).is_err()
    );
}

#[test]
fn live_ed25519_p256_hybrid_policies() {
    let chal = challenge_fixture();
    let ed = SoftwareSigner::from_ed25519_seed([0x11u8; 32]);
    let p256 = SoftwareSigner::from_p256_seed([0x22u8; 32]).unwrap();
    let hybrid = SoftwareSigner::from_ed25519_seed([0x11u8; 32])
        .with_ml_dsa_65()
        .unwrap();

    for signer in [&ed, &p256] {
        let mut store = store_with(&chal);
        let resp = signer.respond(&chal).unwrap();
        verify_response(&resp, AUD, NOW, SKEW, VerifyPolicy::PqOptional, &mut store).unwrap();
    }
    let mut store = store_with(&chal);
    let resp = hybrid.respond(&chal).unwrap();
    verify_response(&resp, AUD, NOW, SKEW, VerifyPolicy::PqRequired, &mut store).unwrap();
    // Downgrade: strip PQ
    let mut stripped = resp.clone();
    stripped.pq = None;
    let mut store = store_with(&chal);
    assert!(
        verify_response(&stripped, AUD, NOW, SKEW, VerifyPolicy::PqRequired, &mut store).is_err()
    );
}

/// Re-encode of the committed challenge must match.
#[test]
fn challenge_bytes_stable() {
    let want = include_bytes!("fixtures/challenge.bin");
    assert_eq!(challenge_fixture().to_bytes(), want);
}

#[test]
#[ignore]
fn write_fixtures() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    std::fs::create_dir_all(&dir).unwrap();
    let chal = challenge_fixture();
    std::fs::write(dir.join("challenge.bin"), chal.to_bytes()).unwrap();
    let ed = SoftwareSigner::from_ed25519_seed([0x11u8; 32]);
    std::fs::write(
        dir.join("response-ed25519.bin"),
        ed.respond(&chal).unwrap().to_bytes(),
    )
    .unwrap();
    let p256 = SoftwareSigner::from_p256_seed([0x22u8; 32]).unwrap();
    std::fs::write(
        dir.join("response-p256.bin"),
        p256.respond(&chal).unwrap().to_bytes(),
    )
    .unwrap();
}
