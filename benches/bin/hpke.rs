use anyhow::Result;
use heli::crypto::hpke::{HpkeEnvelope, ServerKeys, hpke_decrypt, hpke_encrypt};
use std::time::{Duration, Instant};

/// =======================
/// Microbenchmark helpers
/// =======================

fn bench_encrypt(server_keys: &ServerKeys, plaintext: &[u8], iters: usize) -> Result<Duration> {
    let info = b"my-protocol v1 initial-message";
    let aad = b"";

    // Warmup
    for _ in 0..10 {
        let _ = hpke_encrypt(&server_keys.pk, plaintext, info, aad)?;
    }

    let start = Instant::now();
    for _ in 0..iters {
        let _ = hpke_encrypt(&server_keys.pk, plaintext, info, aad)?;
    }
    Ok(start.elapsed())
}

fn bench_decrypt(
    server_keys: &ServerKeys,
    envelope: &HpkeEnvelope,
    iters: usize,
) -> Result<Duration> {
    let info = b"my-protocol v1 initial-message";
    let aad = b"";

    // Warmup
    for _ in 0..10 {
        let _ = hpke_decrypt(&server_keys.sk, envelope, info, aad)?;
    }

    let start = Instant::now();
    for _ in 0..iters {
        let _ = hpke_decrypt(&server_keys.sk, envelope, info, aad)?;
    }
    Ok(start.elapsed())
}

fn main() -> Result<()> {
    let server_keys = ServerKeys::generate();

    let message = b"msg";
    let info = b"info";
    let aad = b"aad";

    let (envelope, _sender_ctx) = hpke_encrypt(&server_keys.pk, message, info, aad)?;
    let (decrypted, _receiver_ctx) = hpke_decrypt(&server_keys.sk, &envelope, info, aad)?;

    assert_eq!(decrypted, message);

    let iters = 1_000;

    let enc_time = bench_encrypt(&server_keys, message, iters)?;
    let dec_time = bench_decrypt(&server_keys, &envelope, iters)?;

    println!("HPKE benchmark ({iters} iterations)");
    println!(
        "Encrypt total: {:?}  (avg {:?})",
        enc_time,
        enc_time / iters as u32
    );
    println!(
        "Decrypt total: {:?}  (avg {:?})",
        dec_time,
        dec_time / iters as u32
    );

    Ok(())
}
