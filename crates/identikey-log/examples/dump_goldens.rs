//! Prints the re-baselined v4 golden vectors. Used to regenerate the pinned
//! constants in tests/goldens.rs and Dreamball's fixtures/goldens/manifest.json.
use identikey_log::{codec, Author, Hlc, Op};

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

fn main() {
    bc_envelope::register_tags();
    let author = Author::from_seed(&[0u8; 32]);
    let op = Op::new("worldtree.kanban-card.move", author.actor(), Hlc::new(1_700_000_000_000, 7))
        .with_body(vec![0x82, 0x01, 0x02])
        .with_parents([[0x10u8; 32]]);
    let unsigned = codec::encode(&op).unwrap();
    println!("actor            {}", hex(&author.actor()));
    println!("unsigned_hex     {}", hex(&unsigned));
    println!("unsigned_blake3  {}", hex(blake3::hash(&unsigned).as_bytes()));
    let signed = author.sign(op.clone()).unwrap();
    let sb = codec::encode_signed(&signed).unwrap();
    println!("signed_hex       {}", hex(&sb));
    println!("signed_blake3    {}", hex(blake3::hash(&sb).as_bytes()));
    println!("--- format ---");
    println!("{}", codec::to_signed_envelope(&signed).unwrap().format());
    println!("--- unsigned format ---");
    println!("{}", codec::to_envelope(&op).unwrap().format());
}
