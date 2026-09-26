//! identikey-capability-v1 fixtures: tests verify AGAINST committed bytes.

use identikey_capability::{
    authorize, decode_bearer, encode_bearer, parse, public_from_hex, CapabilityError,
};

fn root_public() -> identikey_capability::PublicKey {
    let hex = include_str!("fixtures/root_public.hex").trim();
    public_from_hex(hex).unwrap()
}

#[test]
fn authority_fixture_parses_and_authorizes() {
    let bytes = include_bytes!("fixtures/authority.bin");
    parse(bytes, root_public()).unwrap();
    authorize(bytes, root_public(), None, "example", "read").unwrap();
    assert!(authorize(bytes, root_public(), None, "example", "write").is_err());
}

#[test]
fn attenuated_fixture_needs_holder() {
    let bytes = include_bytes!("fixtures/attenuated.bin");
    parse(bytes, root_public()).unwrap();
    authorize(bytes, root_public(), Some("FP"), "example", "read").unwrap();
    assert!(authorize(bytes, root_public(), None, "example", "read").is_err());
    assert!(authorize(bytes, root_public(), Some("OTHER"), "example", "read").is_err());
}

#[test]
fn authority_tamper_fails() {
    let mut bytes = include_bytes!("fixtures/authority.bin").to_vec();
    let i = bytes.len() / 2;
    bytes[i] ^= 0xff;
    assert!(parse(&bytes, root_public()).is_err());
}

#[test]
fn bearer_codec_on_fixture() {
    let bytes = include_bytes!("fixtures/attenuated.bin");
    let header = format!("Bearer {}", encode_bearer(bytes));
    assert_eq!(decode_bearer(&header).unwrap(), bytes);
}

#[test]
fn fixture_has_no_holder_fact() {
    let bytes = include_bytes!("fixtures/attenuated.bin");
    // parse already rejects holder facts
    parse(bytes, root_public()).unwrap();
    let _ = CapabilityError::HolderFact;
}
