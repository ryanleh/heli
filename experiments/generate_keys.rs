//! Generate HPKE keys and output Rust source code.
//!
//! Run with: cargo run --bin generate_keys
//!
//! This outputs the content for src/experiments/keys.rs

use hpke::{Kem, Serializable};

type HpkeKem = hpke::kem::X25519HkdfSha256;

fn format_bytes(bytes: &[u8]) -> String {
    let mut result = String::new();
    for (i, chunk) in bytes.chunks(8).enumerate() {
        if i > 0 {
            result.push_str("\n    ");
        } else {
            result.push_str("    ");
        }
        for (j, byte) in chunk.iter().enumerate() {
            if j > 0 {
                result.push_str(", ");
            }
            result.push_str(&format!("0x{:02x}", byte));
        }
        result.push(',');
    }
    result
}

fn main() {
    let mut rng = rand::rngs::OsRng;

    // Generate aggregator keys
    let (agg_sk, agg_pk) = <HpkeKem as Kem>::gen_keypair(&mut rng);
    let agg_sk_bytes = agg_sk.to_bytes();
    let agg_pk_bytes = agg_pk.to_bytes();

    // Generate decryptor keys
    let (dec_sk, dec_pk) = <HpkeKem as Kem>::gen_keypair(&mut rng);
    let dec_sk_bytes = dec_sk.to_bytes();
    let dec_pk_bytes = dec_pk.to_bytes();

    println!(
        r#"//! Pre-generated HPKE keys for experiments.
//! 
//! Run with: cargo run --bin generate_keys
//! 
//! WARNING: These keys are for benchmarking only. Do not use in production!

use crate::crypto::hpke::ServerKeys;
use hpke::{{Deserializable, Kem}};

type HpkeKem = hpke::kem::X25519HkdfSha256;

/// Aggregator's HPKE secret key (32 bytes)
pub const AGGREGATOR_SK: [u8; 32] = [
{}
];

/// Aggregator's HPKE public key (32 bytes)
pub const AGGREGATOR_PK: [u8; 32] = [
{}
];

/// Decryptor's HPKE secret key (32 bytes)
pub const DECRYPTOR_SK: [u8; 32] = [
{}
];

/// Decryptor's HPKE public key (32 bytes)
pub const DECRYPTOR_PK: [u8; 32] = [
{}
];

/// Load the aggregator's HPKE keys from the embedded constants
pub fn aggregator_keys() -> ServerKeys {{
    let sk = <HpkeKem as Kem>::PrivateKey::from_bytes(&AGGREGATOR_SK)
        .expect("Invalid aggregator secret key");
    let pk = <HpkeKem as Kem>::PublicKey::from_bytes(&AGGREGATOR_PK)
        .expect("Invalid aggregator public key");
    ServerKeys {{ sk, pk }}
}}

/// Load the decryptor's HPKE keys from the embedded constants
pub fn decryptor_keys() -> ServerKeys {{
    let sk = <HpkeKem as Kem>::PrivateKey::from_bytes(&DECRYPTOR_SK)
        .expect("Invalid decryptor secret key");
    let pk = <HpkeKem as Kem>::PublicKey::from_bytes(&DECRYPTOR_PK)
        .expect("Invalid decryptor public key");
    ServerKeys {{ sk, pk }}
}}"#,
        format_bytes(agg_sk_bytes.as_slice()),
        format_bytes(agg_pk_bytes.as_slice()),
        format_bytes(dec_sk_bytes.as_slice()),
        format_bytes(dec_pk_bytes.as_slice()),
    );
}
