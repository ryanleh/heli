use anyhow::{Result, anyhow};

use hpke::{
    Deserializable,
    OpModeR,
    OpModeS,
    Serializable, // to avoid weird versioning errors
    aead::{AeadCtxR, AeadCtxS},
    rand_core::OsRng, // to avoid weird versioning errors
    setup_receiver,
    setup_sender,
};

/// Algorithm choices
type Kem = hpke::kem::X25519HkdfSha256;
type Kdf = hpke::kdf::HkdfSha256;
type Aead = hpke::aead::ChaCha20Poly1305;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct HpkeEnvelope {
    enc: Vec<u8>, // Encrypted symmetric key
    ct: Vec<u8>,  // Encrypted data
}

#[derive(Clone)]
pub struct ServerKeys {
    pub sk: <Kem as hpke::Kem>::PrivateKey,
    pub pk: <Kem as hpke::Kem>::PublicKey,
}

impl ServerKeys {
    pub fn generate() -> Self {
        let (sk, pk) = <Kem as hpke::Kem>::gen_keypair(&mut OsRng);
        Self { sk, pk }
    }
}

/// HPKE encryption
pub fn hpke_encrypt(
    public_key: &<Kem as hpke::Kem>::PublicKey,
    plaintext: &[u8],
    info: &[u8],
    aad: &[u8],
) -> Result<(HpkeEnvelope, AeadCtxS<Aead, Kdf, Kem>)> {
    let (enc, mut sender_ctx) =
        setup_sender::<Aead, Kdf, Kem, _>(&OpModeS::Base, &public_key, info, &mut OsRng)
            .map_err(|e| anyhow!("HPKE setup error: {e:?}"))?;

    let ct = sender_ctx
        .seal(plaintext, aad)
        .map_err(|e| anyhow!("HPKE sealing error: {e:?}"))?;

    Ok((
        HpkeEnvelope {
            enc: enc.to_bytes().to_vec(),
            ct,
        },
        sender_ctx,
    ))
}

/// HPKE decryption
pub fn hpke_decrypt(
    server_sk: &<Kem as hpke::Kem>::PrivateKey,
    envelope: &HpkeEnvelope,
    info: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, AeadCtxR<Aead, Kdf, Kem>)> {
    let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(&envelope.enc)
        .map_err(|e| anyhow!("HPKE error: {e:?}"))?;
    let mut receiver_ctx = setup_receiver::<Aead, Kdf, Kem>(&OpModeR::Base, server_sk, &enc, info)
        .map_err(|e| anyhow!("HPKE setup error: {e:?}"))?;

    let plaintext = receiver_ctx
        .open(&envelope.ct, aad)
        .map_err(|e| anyhow!("HPKE opening error: {e:?}"))?;

    Ok((plaintext, receiver_ctx))
}

/// Encryption using an existing HPKE context
pub fn hpke_encrypt_with_context(
    sender_ctx: &mut AeadCtxS<Aead, Kdf, Kem>,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    sender_ctx
        .seal(plaintext, aad)
        .map_err(|e| anyhow!("HPKE sealing error: {e:?}"))
}

/// Decryption using an existing HPKE context
pub fn hpke_decrypt_with_context(
    receiver_ctx: &mut AeadCtxR<Aead, Kdf, Kem>,
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    receiver_ctx
        .open(ciphertext, aad)
        .map_err(|e| anyhow!("HPKE opening error: {e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_encrypt_decrypt() {
        let server_keys = ServerKeys::generate();
        let plaintext = b"Hello, HPKE!";
        let info = b"test-info";
        let aad = b"test-aad";

        // Encrypt
        let (envelope, _sender_ctx) =
            hpke_encrypt(&server_keys.pk, plaintext, info, aad).expect("Encryption should succeed");

        // Decrypt
        let (decrypted, _receiver_ctx) =
            hpke_decrypt(&server_keys.sk, &envelope, info, aad).expect("Decryption should succeed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_empty_plaintext() {
        let server_keys = ServerKeys::generate();
        let plaintext = b"";
        let info = b"test-info";
        let aad = b"test-aad";

        let (envelope, _sender_ctx) =
            hpke_encrypt(&server_keys.pk, plaintext, info, aad).expect("Encryption should succeed");

        let (decrypted, _receiver_ctx) =
            hpke_decrypt(&server_keys.sk, &envelope, info, aad).expect("Decryption should succeed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_large_plaintext() {
        let server_keys = ServerKeys::generate();
        let plaintext: Vec<u8> = (0..10000u32).map(|i| (i % 256) as u8).collect();
        let info = b"test-info";
        let aad = b"test-aad";

        let (envelope, _sender_ctx) = hpke_encrypt(&server_keys.pk, &plaintext, info, aad)
            .expect("Encryption should succeed");

        let (decrypted, _receiver_ctx) =
            hpke_decrypt(&server_keys.sk, &envelope, info, aad).expect("Decryption should succeed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_private_key() {
        let server_keys1 = ServerKeys::generate();
        let server_keys2 = ServerKeys::generate();
        let plaintext = b"secret message";
        let info = b"test-info";
        let aad = b"test-aad";

        // Encrypt with server_keys1's public key
        let (envelope, _sender_ctx) = hpke_encrypt(&server_keys1.pk, plaintext, info, aad)
            .expect("Encryption should succeed");

        // Try to decrypt with server_keys2's private key (should fail)
        let result = hpke_decrypt(&server_keys2.sk, &envelope, info, aad);
        assert!(result.is_err(), "Decryption with wrong key should fail");
    }

    #[test]
    fn test_wrong_info() {
        let server_keys = ServerKeys::generate();
        let plaintext = b"secret message";
        let info1 = b"correct-info";
        let info2 = b"wrong-info";
        let aad = b"test-aad";

        let (envelope, _sender_ctx) = hpke_encrypt(&server_keys.pk, plaintext, info1, aad)
            .expect("Encryption should succeed");

        // Try to decrypt with wrong info (should fail)
        let result = hpke_decrypt(&server_keys.sk, &envelope, info2, aad);
        assert!(result.is_err(), "Decryption with wrong info should fail");
    }

    #[test]
    fn test_wrong_aad() {
        let server_keys = ServerKeys::generate();
        let plaintext = b"secret message";
        let info = b"test-info";
        let aad1 = b"correct-aad";
        let aad2 = b"wrong-aad";

        let (envelope, _sender_ctx) = hpke_encrypt(&server_keys.pk, plaintext, info, aad1)
            .expect("Encryption should succeed");

        // Try to decrypt with wrong aad (should fail)
        let result = hpke_decrypt(&server_keys.sk, &envelope, info, aad2);
        assert!(result.is_err(), "Decryption with wrong aad should fail");
    }

    #[test]
    fn test_nonce_randomness() {
        let server_keys = ServerKeys::generate();
        let plaintext = b"same message";
        let info = b"test-info";
        let aad = b"test-aad";

        // Encrypt the same message twice
        let (envelope1, _sender_ctx1) =
            hpke_encrypt(&server_keys.pk, plaintext, info, aad).expect("Encryption should succeed");
        let (envelope2, _sender_ctx2) =
            hpke_encrypt(&server_keys.pk, plaintext, info, aad).expect("Encryption should succeed");

        // The ciphertexts should be different due to randomness
        assert_ne!(envelope1.ct, envelope2.ct, "Ciphertexts should differ");
        assert_ne!(
            envelope1.enc, envelope2.enc,
            "Encapsulated keys should differ"
        );

        // But both should decrypt to the same plaintext
        let (decrypted1, _receiver_ctx1) = hpke_decrypt(&server_keys.sk, &envelope1, info, aad)
            .expect("Decryption should succeed");
        let (decrypted2, _receiver_ctx2) = hpke_decrypt(&server_keys.sk, &envelope2, info, aad)
            .expect("Decryption should succeed");

        assert_eq!(decrypted1, plaintext);
        assert_eq!(decrypted2, plaintext);
    }

    #[test]
    fn test_empty_info_and_aad() {
        let server_keys = ServerKeys::generate();
        let plaintext = b"message";
        let info = b"";
        let aad = b"";

        let (envelope, _sender_ctx) =
            hpke_encrypt(&server_keys.pk, plaintext, info, aad).expect("Encryption should succeed");

        let (decrypted, _receiver_ctx) =
            hpke_decrypt(&server_keys.sk, &envelope, info, aad).expect("Decryption should succeed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_with_context() {
        let server_keys = ServerKeys::generate();
        let info = b"test-info";
        let aad = b"test-aad";

        // Initial encryption to establish context
        let plaintext1 = b"first message";
        let (envelope1, mut sender_ctx) = hpke_encrypt(&server_keys.pk, plaintext1, info, aad)
            .expect("Encryption should succeed");

        // Decrypt first message and get receiver context
        let (decrypted1, mut receiver_ctx) = hpke_decrypt(&server_keys.sk, &envelope1, info, aad)
            .expect("Decryption should succeed");
        assert_eq!(decrypted1, plaintext1);

        // Encrypt additional messages using the context
        let plaintext2 = b"second message";
        let plaintext3 = b"third message";

        let ct2 = hpke_encrypt_with_context(&mut sender_ctx, plaintext2, aad)
            .expect("Context encryption should succeed");
        let ct3 = hpke_encrypt_with_context(&mut sender_ctx, plaintext3, aad)
            .expect("Context encryption should succeed");

        // Decrypt using the receiver context
        let decrypted2 = hpke_decrypt_with_context(&mut receiver_ctx, &ct2, aad)
            .expect("Context decryption should succeed");
        let decrypted3 = hpke_decrypt_with_context(&mut receiver_ctx, &ct3, aad)
            .expect("Context decryption should succeed");

        assert_eq!(decrypted2, plaintext2);
        assert_eq!(decrypted3, plaintext3);
    }

    #[test]
    fn test_context_multiple_messages() {
        let server_keys = ServerKeys::generate();
        let info = b"test-info";
        let aad = b"test-aad";

        // Establish session
        let (envelope, mut sender_ctx) =
            hpke_encrypt(&server_keys.pk, b"init", info, aad).expect("Encryption should succeed");
        let (_decrypted, mut receiver_ctx) =
            hpke_decrypt(&server_keys.sk, &envelope, info, aad).expect("Decryption should succeed");

        // Send multiple messages
        let messages = vec![
            b"message 1".as_slice(),
            b"message 2".as_slice(),
            b"message 3".as_slice(),
            b"message 4".as_slice(),
        ];

        let mut ciphertexts = Vec::new();
        for msg in &messages {
            let ct = hpke_encrypt_with_context(&mut sender_ctx, msg, aad)
                .expect("Context encryption should succeed");
            ciphertexts.push(ct);
        }

        // Decrypt all messages
        for (i, ct) in ciphertexts.iter().enumerate() {
            let decrypted = hpke_decrypt_with_context(&mut receiver_ctx, ct, aad)
                .expect("Context decryption should succeed");
            assert_eq!(decrypted, messages[i]);
        }
    }

    #[test]
    fn test_context_wrong_aad() {
        let server_keys = ServerKeys::generate();
        let info = b"test-info";
        let aad1 = b"correct-aad";
        let aad2 = b"wrong-aad";

        // Establish session
        let (envelope, mut sender_ctx) =
            hpke_encrypt(&server_keys.pk, b"init", info, aad1).expect("Encryption should succeed");
        let (_decrypted, mut receiver_ctx) = hpke_decrypt(&server_keys.sk, &envelope, info, aad1)
            .expect("Decryption should succeed");

        // Encrypt with correct aad
        let plaintext = b"secret message";
        let ct = hpke_encrypt_with_context(&mut sender_ctx, plaintext, aad1)
            .expect("Context encryption should succeed");

        // Try to decrypt with wrong aad (should fail)
        let result = hpke_decrypt_with_context(&mut receiver_ctx, &ct, aad2);
        assert!(
            result.is_err(),
            "Context decryption with wrong aad should fail"
        );
    }

    #[test]
    fn test_context_empty_plaintext() {
        let server_keys = ServerKeys::generate();
        let info = b"test-info";
        let aad = b"test-aad";

        // Establish session
        let (envelope, mut sender_ctx) =
            hpke_encrypt(&server_keys.pk, b"init", info, aad).expect("Encryption should succeed");
        let (_decrypted, mut receiver_ctx) =
            hpke_decrypt(&server_keys.sk, &envelope, info, aad).expect("Decryption should succeed");

        // Encrypt empty message
        let plaintext = b"";
        let ct = hpke_encrypt_with_context(&mut sender_ctx, plaintext, aad)
            .expect("Context encryption should succeed");

        let decrypted = hpke_decrypt_with_context(&mut receiver_ctx, &ct, aad)
            .expect("Context decryption should succeed");

        assert_eq!(decrypted, plaintext);
    }
}
