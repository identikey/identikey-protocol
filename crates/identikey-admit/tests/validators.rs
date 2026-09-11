//! Pure validators for the admit protocol (v1 shape check).

use identikey_admit::{
    AdmitError, Attestation, ENVELOPE_VERSION, Envelope, Verdict, attestation, thaw_allowed,
};
use serde_json::{Value, json};

#[test]
fn crate_must_not_depend_on_identikey_core() {
    let manifest = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));
    assert!(
        !manifest.contains("identikey-core ="),
        "identikey-admit must not depend on identikey-core"
    );
    assert!(
        !manifest.contains("identikey-auth ="),
        "identikey-admit must not pull identikey-auth"
    );
    let workspace = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.toml"));
    assert!(
        !workspace.contains("identikey-core"),
        "workspace must not name identikey-core as a member"
    );
}

#[test]
fn matching_vm_id_and_epoch_is_allow() {
    let payload = json!({"attestation": {"vm_id": "vm-1", "epoch": 0}});
    assert!(thaw_allowed("vm-1", &payload));
    let payload = json!({"attestation": {"vm_id": "vm-1", "epoch": 3}});
    assert!(thaw_allowed("vm-1", &payload));
}

#[test]
fn missing_attestation_is_deny() {
    assert!(!thaw_allowed("vm-1", &json!({"wake": true})));
    assert!(!thaw_allowed("vm-1", &Value::Null));
    assert!(!thaw_allowed("vm-1", &json!("not a map")));
}

#[test]
fn mismatched_vm_id_is_deny() {
    let payload = json!({"attestation": {"vm_id": "other", "epoch": 0}});
    assert!(!thaw_allowed("vm-1", &payload));
}

#[test]
fn non_integer_epoch_is_deny() {
    assert!(!thaw_allowed(
        "vm-1",
        &json!({"attestation": {"vm_id": "vm-1", "epoch": "0"}})
    ));
    assert!(!thaw_allowed(
        "vm-1",
        &json!({"attestation": {"vm_id": "vm-1", "epoch": 1.5}})
    ));
}

#[test]
fn negative_epoch_is_invalid() {
    let err = Attestation::from_value(&json!({"vm_id": "vm-1", "epoch": -1})).unwrap_err();
    assert_eq!(err, AdmitError::InvalidEpoch);
    assert!(!thaw_allowed(
        "vm-1",
        &json!({"attestation": {"vm_id": "vm-1", "epoch": -1}})
    ));
}

#[test]
fn empty_vm_id_is_invalid() {
    assert_eq!(Attestation::new("", 0).unwrap_err(), AdmitError::EmptyVmId);
    assert_eq!(
        Attestation::from_value(&json!({"vm_id": "", "epoch": 0})).unwrap_err(),
        AdmitError::EmptyVmId
    );
}

#[test]
fn attestation_round_trip() {
    let att = Attestation::new("vm-1", 7).unwrap();
    let parsed = Attestation::from_value(&att.to_value()).unwrap();
    assert_eq!(att, parsed);
    assert!(parsed.valid_for("vm-1"));
    assert!(!parsed.valid_for("vm-2"));
}

#[test]
fn envelope_parses_elixir_shaped_payload() {
    let payload = json!({"attestation": {"vm_id": "vm-1", "epoch": 0}});
    let env = Envelope::from_value(&payload).unwrap();
    assert_eq!(env.version, ENVELOPE_VERSION);
    assert!(env.valid_for("vm-1"));
    assert_eq!(attestation(&payload).unwrap().vm_id, "vm-1");
}

#[test]
fn envelope_rejects_unknown_version() {
    let payload = json!({
        "version": 2,
        "attestation": {"vm_id": "vm-1", "epoch": 0}
    });
    assert_eq!(
        Envelope::from_value(&payload).unwrap_err(),
        AdmitError::UnsupportedVersion(2)
    );
}

#[test]
fn envelope_bytes_round_trip() {
    let env = Envelope::new(Attestation::new("abc", 1).unwrap());
    let bytes = serde_json::to_vec(&env.to_value()).unwrap();
    let parsed = Envelope::from_slice(&bytes).unwrap();
    assert_eq!(env, parsed);
}

#[test]
fn verdict_vocabulary() {
    assert_eq!(Verdict::parse("deny").unwrap(), Verdict::Deny);
    assert_eq!(Verdict::parse("drop").unwrap(), Verdict::Drop);
    assert_eq!(Verdict::parse("reply-here").unwrap(), Verdict::ReplyHere);
    assert_eq!(Verdict::parse("deliver").unwrap(), Verdict::Deliver);
    assert_eq!(Verdict::Deny.as_str(), "deny");
    assert_eq!(Verdict::Drop.as_str(), "drop");
    assert_eq!(Verdict::ReplyHere.as_str(), "reply-here");
    assert_eq!(Verdict::Deliver.as_str(), "deliver");
    assert_eq!(
        Verdict::parse("allow").unwrap_err(),
        AdmitError::UnknownVerdict("allow".into())
    );
    assert_eq!(Verdict::Deliver.to_string(), "deliver");
}
