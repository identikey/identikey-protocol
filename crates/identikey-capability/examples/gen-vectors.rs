//! One-shot: print committed vector bytes for identikey-capability-v1.
//! Run: cargo run -p identikey-capability --example gen-vectors

use identikey_capability::{
    append_holder_check, encode_bearer, keypair_from_private_hex, mint_right, parse,
};

fn main() {
    let root = keypair_from_private_hex(&"11".repeat(32)).expect("root");
    let minted = mint_right(&root, "example", "read").expect("mint");
    let tok = parse(&minted, root.public()).expect("parse");
    let held = append_holder_check(&tok, "FP").expect("hold");
    println!("root_public_hex={}", hex::encode(root.public().to_bytes()));
    println!("authority_hex={}", hex::encode(&minted));
    println!("attenuated_hex={}", hex::encode(&held));
    println!("bearer={}", encode_bearer(&held));
}
