//! End-to-end demo of the hardware-enclave + biometric auth path.
//!
//! - **macOS**: Secure Enclave P-256 key + Touch ID. Build with `--features enclave`
//!   and run a code-signed binary
//!   (`codesign --sign "Developer ID Application: …" target/debug/examples/enclave_demo`).
//! - **Windows**: TPM-backed P-256 key via the Platform Crypto Provider. Runs headless
//!   (needs a TPM / vTPM); the ephemeral key uses no Windows Hello prompt.
//!
//! Expected output ends with `VERIFIED identity: <fingerprint>`. On other platforms this
//! example is a no-op.

#[cfg(all(
    feature = "enclave",
    any(target_os = "macos", target_os = "windows", target_os = "linux"),
))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use identikey_auth::{
        ChallengeIssuer, InMemoryNonceStore, Signer, VerifyPolicy, verify_response,
    };

    let now = 1_000_000u64;

    // 1. Verifier issues a challenge.
    let mut nonces = InMemoryNonceStore::new();
    let challenge = ChallengeIssuer::new("papyrus", 120).issue(&mut nonces, now);
    println!("issued challenge for audience 'papyrus'");

    // 2. Claimant signs it with an ephemeral hardware key (no entitlement / no prompt).
    #[cfg(all(target_os = "macos", feature = "enclave"))]
    let signer =
        identikey_auth::SecureEnclaveSigner::create_ephemeral("io.identikey.papyrus.device")?;
    #[cfg(all(feature = "enclave", any(target_os = "windows", target_os = "linux")))]
    let signer = identikey_auth::TpmSigner::create_ephemeral()?;

    println!(
        "device fingerprint: {}",
        signer.classical_public_key().fingerprint()
    );
    let response = signer.respond(&challenge)?;
    println!("signed challenge with hardware P-256 key");

    // 3. Verifier checks the response.
    let verified = verify_response(
        &response,
        "papyrus",
        now,
        30,
        VerifyPolicy::PqOptional,
        &mut nonces,
    )?;
    println!("VERIFIED identity: {}", verified.fingerprint);
    assert_eq!(verified.public_key, signer.classical_public_key());
    Ok(())
}

#[cfg(not(all(
    feature = "enclave",
    any(target_os = "macos", target_os = "windows", target_os = "linux"),
)))]
fn main() {
    eprintln!(
        "enclave_demo needs --features enclave on macOS (Secure Enclave), Windows, or Linux (TPM)"
    );
}
