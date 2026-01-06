use anyhow::{Context, Result, anyhow, bail};
use ring::signature::{ED25519, Ed25519KeyPair, Signature, UnparsedPublicKey};
use x509_parser::prelude::*;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

// Actual Apple attestation object from https://github.com/bas-d/appattest
pub const ATTESTATION: &str = "o2NmbXRvYXBwbGUtYXBwYXR0ZXN0Z2F0dFN0bXSiY3g1Y4JZAuswggLnMIICbaADAgECAgYBeNT03AYwCgYIKoZIzj0EAwIwTzEjMCEGA1UEAwwaQXBwbGUgQXBwIEF0dGVzdGF0aW9uIENBIDExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwHhcNMjEwNDE0MDk1NTIwWhcNMjEwNDE3MDk1NTIwWjCBkTFJMEcGA1UEAwxAMDFjM2ZmYTY3YTY4MzU1M2M4MjU4NjRlYmU2MjJmNWIzMGVmOWIxOTA1YTEwMDg0ZTE0YmJiMzY0ZTk2ODgwMDEaMBgGA1UECwwRQUFBIENlcnRpZmljYXRpb24xEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ3xAT6K7-PvPTucIBXPV-oDE9sw6IvfbQ6-Sw5TnzRyIDJWrQilyYl6OZzrxvaKwlmVOm2AolWAfklu1lBxTCCo4HxMIHuMAwGA1UdEwEB_wQCMAAwDgYDVR0PAQH_BAQDAgTwMH4GCSqGSIb3Y2QIBQRxMG-kAwIBCr-JMAMCAQG_iTEDAgEAv4kyAwIBAb-JMwMCAQG_iTQmBCQzNU1GWVkySlk1LmNvLmNoaWZmLmF0dGVzdGF0aW9uLXRlc3SlBgQEc2tzIL-JNgMCAQW_iTcDAgEAv4k5AwIBAL-JOgMCAQAwGQYJKoZIhvdjZAgHBAwwCr-KeAYEBDE0LjQwMwYJKoZIhvdjZAgCBCYwJKEiBCCOPSSk1ZLu7Zc9Zd2TmGO7tY5ktIclyAclmfTBJdpmjjAKBggqhkjOPQQDAgNoADBlAjEAzHk20GzLdZlaaJXKchriZkmJWhfTCgQHRpn3D6Y7Coit7UQABhIABVh6D4qwPysZAjAFDGuGqb796A9H-1UVCgui5ufZnWZHl1SVT-6iobxfS9av2ahGkLF8hYQXVT3pofxZAkcwggJDMIIByKADAgECAhAJusXhvEAa2dRTlbw4GghUMAoGCCqGSM49BAMDMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlvbiBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMB4XDTIwMDMxODE4Mzk1NVoXDTMwMDMxMzAwMDAwMFowTzEjMCEGA1UEAwwaQXBwbGUgQXBwIEF0dGVzdGF0aW9uIENBIDExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASuWzegd015sjWPQOfR8iYm8cJf7xeALeqzgmpZh0_40q0VJXiaomYEGRJItjy5ZwaemNNjvV43D7-gjjKegHOphed0bqNZovZvKdsyr0VeIRZY1WevniZ-smFNwhpmzpmjZjBkMBIGA1UdEwEB_wQIMAYBAf8CAQAwHwYDVR0jBBgwFoAUrJEQUzO9vmhB_6cMqeX66uXliqEwHQYDVR0OBBYEFD7jXRwEGanJtDH4hHTW4eFXcuObMA4GA1UdDwEB_wQEAwIBBjAKBggqhkjOPQQDAwNpADBmAjEAu76IjXONBQLPvP1mbQlXUDW81ocsP4QwSSYp7dH5FOh5mRya6LWu-NOoVDP3tg0GAjEAqzjt0MyB7QCkUsO6RPmTY2VT_swpfy60359evlpKyraZXEuCDfkEOG94B7tYlDm3Z3JlY2VpcHRZDl0wgAYJKoZIhvcNAQcCoIAwgAIBATEPMA0GCWCGSAFlAwQCAQUAMIAGCSqGSIb3DQEHAaCAJIAEggPoMYIEGDAsAgECAgEBBCQzNU1GWVkySlk1LmNvLmNoaWZmLmF0dGVzdGF0aW9uLXRlc3QwggL1AgEDAgEBBIIC6zCCAucwggJtoAMCAQICBgF41PTcBjAKBggqhkjOPQQDAjBPMSMwIQYDVQQDDBpBcHBsZSBBcHAgQXR0ZXN0YXRpb24gQ0EgMTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMTA0MTQwOTU1MjBaFw0yMTA0MTcwOTU1MjBaMIGRMUkwRwYDVQQDDEAwMWMzZmZhNjdhNjgzNTUzYzgyNTg2NGViZTYyMmY1YjMwZWY5YjE5MDVhMTAwODRlMTRiYmIzNjRlOTY4ODAwMRowGAYDVQQLDBFBQUEgQ2VydGlmaWNhdGlvbjETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDfEBPorv4-89O5wgFc9X6gMT2zDoi99tDr5LDlOfNHIgMlatCKXJiXo5nOvG9orCWZU6bYCiVYB-SW7WUHFMIKjgfEwge4wDAYDVR0TAQH_BAIwADAOBgNVHQ8BAf8EBAMCBPAwfgYJKoZIhvdjZAgFBHEwb6QDAgEKv4kwAwIBAb-JMQMCAQC_iTIDAgEBv4kzAwIBAb-JNCYEJDM1TUZZWTJKWTUuY28uY2hpZmYuYXR0ZXN0YXRpb24tdGVzdKUGBARza3Mgv4k2AwIBBb-JNwMCAQC_iTkDAgEAv4k6AwIBADAZBgkqhkiG92NkCAcEDDAKv4p4BgQEMTQuNDAzBgkqhkiG92NkCAIEJjAkoSIEII49JKTVku7tlz1l3ZOYY7u1jmS0hyXIByWZ9MEl2maOMAoGCCqGSM49BAMCA2gAMGUCMQDMeTbQbMt1mVpolcpyGuJmSYlaF9MKBAdGmfcPpjsKiK3tRAAGEgAFWHoPirA_KxkCMAUMa4apvv3oD0f7VRUKC6Lm59mdZkeXVJVP7qKhvF9L1q_ZqEaQsXyFhBdVPemh_DAoAgEEAgEBBCBsbdptlEbTsu5ktHjBTEiDsfbajKOKz4hxgskGW0mjojBgAgEFAgEBBFgxZzZKcm5JdXg5eHFzWDFzSDQ1ekUwUzVvWGJCM0Njenp3aVpZOXJxSkMxc2ZWa3J0T3ZIRk92UXF5Wjg1NE80Yk5zOEloWkV1eVRzNmZPQ01VMmtlZz09MA4CAQYCAQEEBkFUVEVTVDAPAgEHAgEBBAdzYW5kYm94MCACAQwCAQEEGDIwMjEtMAQ0NC0xNVQwOTo1NToyMC4yMDdaMCACARUCAQEEGDIwMjEtMDctMTRUMDk6NTU6MjAuMjA3WgAAAAAAAKCAMIIDrTCCA1SgAwIBAgIQWTNWreVZgs9EQjes30UbUzAKBggqhkjOPQQDAjB8MTAwLgYDVQQDDCdBcHBsZSBBcHBsaWNhdGlvbiBJbnRlZ3JhdGlvbiBDQSA1IC0gRzExJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzAeFw0yMDA1MTkxNzQ3MzFaFw0yMTA2MTgxNzQ3MzFaMFoxNjA0BgNVBAMMLUFwcGxpY2F0aW9uIEF0dGVzdGF0aW9uIEZyYXVkIFJlY2VpcHQgU2lnbmluZzETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR_6RU0bMOKe5g8k9HQQ1_Yq9pWcATTLFiGZVGVerR498sq-LpF9_p46sYsSeT5zcCEtQMU8QIz2pt2-kQqK7hyo4IB2DCCAdQwDAYDVR0TAQH_BAIwADAfBgNVHSMEGDAWgBTZF_5LZ5A4S5L0287VV4AUC489yTBDBggrBgEFBQcBAQQ3MDUwMwYIKwYBBQUHMAGGJ2h0dHA6Ly9vY3NwLmFwcGxlLmNvbS9vY3NwMDMtYWFpY2E1ZzEwMTCCARwGA1UdIASCARMwggEPMIIBCwYJKoZIhvdjZAUBMIH9MIHDBggrBgEFBQcCAjCBtgyBs1JlbGlhbmNlIG9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3VtZXMgYWNjZXB0YW5jZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBjb25kaXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZpY2F0aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMDUGCCsGAQUFBwIBFilodHRwOi8vd3d3LmFwcGxlLmNvbS9jZXJ0aWZpY2F0ZWF1dGhvcml0eTAdBgNVHQ4EFgQUaR7HD0fs443ddTdE8-nhWmwQViUwDgYDVR0PAQH_BAQDAgeAMA8GCSqGSIb3Y2QMDwQCBQAwCgYIKoZIzj0EAwIDRwAwRAIgJRgWXF4pnFn2hTmtXduZ9jc-9g7NCEWp_Xca1iQtLCICIF0qmypfq6NjgWWNGED3r0gL12uhlNg0IIf01pNbtRuuMIIC-TCCAn-gAwIBAgIQVvuD1Cv_jcM3mSO1Wq5uvTAKBggqhkjOPQQDAzBnMRswGQYDVQQDDBJBcHBsZSBSb290IENBIC0gRzMxJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzAeFw0xOTAzMjIxNzUzMzNaFw0zNDAzMjIwMDAwMDBaMHwxMDAuBgNVBAMMJ0FwcGxlIEFwcGxpY2F0aW9uIEludGVncmF0aW9uIENBIDUgLSBHMTEmMCQGA1UECwwdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEks5jvX2GsasoCjsc4a_7BJSAkaz2Md-myyg1b0RL4SHlV90SjY26gnyVvkn6vjPKrs0EGfEvQyX69L6zy4N-uqOB9zCB9DAPBgNVHRMBAf8EBTADAQH_MB8GA1UdIwQYMBaAFLuw3qFYM4iapIqZ3r6966_ayySrMEYGCCsGAQUFBwEBBDowODA2BggrBgEFBQcwAYYqaHR0cDovL29jc3AuYXBwbGUuY29tL29jc3AwMy1hcHBsZXJvb3RjYWczMDcGA1UdHwQwMC4wLKAqoCiGJmh0dHA6Ly9jcmwuYXBwbGUuY29tL2FwcGxlcm9vdGNhZzMuY3JsMB0GA1UdDgQWBBTZF_5LZ5A4S5L0287VV4AUC489yTAOBgNVHQ8BAf8EBAMCAQYwEAYKKoZIhvdjZAYCAwQCBQAwCgYIKoZIzj0EAwMDaAAwZQIxAI1vpp-h4OTsW05zipJ_PXhTmI_02h9YHsN1Sv44qEwqgxoaqg2mZG3huZPo0VVM7QIwZzsstOHoNwd3y9XsdqgaOlU7PzVqyMXmkrDhYb6ASWnkXyupbOERAqrMYdk4t3NKMIICQzCCAcmgAwIBAgIILcX8iNLFS5UwCgYIKoZIzj0EAwMwZzEbMBkGA1UEAwwSQXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcNMTQwNDMwMTgxOTA2WhcNMzkwNDMwMTgxOTA2WjBnMRswGQYDVQQDDBJBcHBsZSBSb290IENBIC0gRzMxJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IABJjpLz1AcqTtkyJygRMc3RCV8cWjTnHcFBbZDuWmBSp3ZHtfTjjTuxxEtX_1H7YyYl3J6YRbTzBPEVoA_VhYDKX1DyxNB0cTddqXl5dvMVztK517IDvYuVTZXpmkOlEKMaNCMEAwHQYDVR0OBBYEFLuw3qFYM4iapIqZ3r6966_ayySrMA8GA1UdEwEB_wQFMAMBAf8wDgYDVR0PAQH_BAQDAgEGMAoGCCqGSM49BAMDA2gAMGUCMQCD6cHEFl4aXTQY2e3v9GwOAEZLuN-yRhHFD_3meoyhpmvOwgPUnPWTxnS4at-qIxUCMG1mihDK1A3UT82NQz60imOlM27jbdoXt2QfyFMm-YhidDkLF1vLUagM6BgD56KyKAAAMYH9MIH6AgEBMIGQMHwxMDAuBgNVBAMMJ0FwcGxlIEFwcGxpY2F0aW9uIEludGVncmF0aW9uIENBIDUgLSBHMTEmMCQGA1UECwwdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTAhBZM1at5VmCz0RCN6zfRRtTMA0GCWCGSAFlAwQCAQUAMAoGCCqGSM49BAMCBEcwRQIgUEClatNpJhJevokCcdbzCvmLPTGKgCpqTcAqo75reeACIQD6mKXj7_E__f78hraVFpg1Bgu44k8zimIrwFpp_5YogAAAAAAAAGhhdXRoRGF0YVikfO8rVdpyQQi6kSeW9nX_AL5x1S2uJo-miNNMptJ_cHRAAAAAAGFwcGF0dGVzdGRldmVsb3AAIAHD_6Z6aDVTyCWGTr5iL1sw75sZBaEAhOFLuzZOlogApQECAyYgASFYIDfEBPorv4-89O5wgFc9X6gMT2zDoi99tDr5LDlOfNHIIlgggMlatCKXJiXo5nOvG9orCWZU6bYCiVYB-SW7WUHFMII";

// Mock client private and public keys used to simulate signing challenges.
// We use these since we don't have the private key for the cert inside
// the apple attestation
const MOCK_PRIVATE_KEY_PKCS8: &[u8] = &[
    0x30, 0x51, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    0x0E, 0x2F, 0xEE, 0xDB, 0xFD, 0x04, 0xB4, 0xDC, 0x54, 0xCE, 0x89, 0x9E, 0x25, 0x3B, 0x84, 0x40,
    0xCA, 0x6A, 0x1B, 0x33, 0x76, 0x4E, 0x26, 0x14, 0xF2, 0x14, 0x11, 0x41, 0x0B, 0x1C, 0xB6, 0x77,
    0x81, 0x21, 0x00, 0x9F, 0xDB, 0x72, 0xF8, 0xB8, 0x7E, 0xC6, 0x78, 0xC3, 0x35, 0x53, 0xF7, 0xE2,
    0xCE, 0x01, 0xFA, 0x3C, 0xAA, 0x7B, 0x79, 0xDF, 0xD3, 0xAC, 0xB0, 0x26, 0xF1, 0x39, 0xC1, 0x87,
    0x22, 0xD6, 0xD2,
];
const MOCK_PUBLIC_KEY: &[u8] = &[
    0x9F, 0xDB, 0x72, 0xF8, 0xB8, 0x7E, 0xC6, 0x78, 0xC3, 0x35, 0x53, 0xF7, 0xE2, 0xCE, 0x01, 0xFA,
    0x3C, 0xAA, 0x7B, 0x79, 0xDF, 0xD3, 0xAC, 0xB0, 0x26, 0xF1, 0x39, 0xC1, 0x87, 0x22, 0xD6, 0xD2,
];

// Verifies the Apple attestation object. This only performs cert verification
// (the main computational overhead) and skips several lower-level checks.
pub fn verify_app_attest(attestation: &str) -> Result<()> {
    use serde_cbor::Value::*;

    // Decode the base64 attestation object
    let attestation_bytes = URL_SAFE_NO_PAD
        .decode(attestation)
        .context("Failed to decode attestation")?;

    // Parse CBOR encoded attestation
    let attestation = match serde_cbor::from_slice(&attestation_bytes)? {
        Map(m) => m,
        _ => bail!("expected CBOR map"),
    };

    let _auth_data = attestation
        .get(&Text("authData".into()))
        .and_then(|v| if let Bytes(b) = v { Some(b) } else { None })
        .context("missing authData")?;

    let attest_stmt = attestation
        .get(&Text("attStmt".into()))
        .and_then(|v| if let Map(m) = v { Some(m) } else { None })
        .context("missing attStmt")?;

    // Extract and parse certificates
    let x5c = attest_stmt
        .get(&Text("x5c".into()))
        .and_then(|v| if let Array(a) = v { Some(a) } else { None })
        .filter(|a| a.len() == 2)
        .context("expected leaf + intermediate certs")?;

    let leaf_cert = if let Bytes(b) = &x5c[0] {
        X509Certificate::from_der(b)?.1
    } else {
        bail!("invalid leaf cert");
    };

    let inter_cert = if let Bytes(b) = &x5c[1] {
        X509Certificate::from_der(b)?.1
    } else {
        bail!("invalid intermediate cert");
    };

    // Verify certificate chain.
    //
    // NOTE: In a real deployment, the intermediate cert will be the same for all users and the
    // light server can verify it once against the root. So all we need to do here is verify the
    // leaf certificate against the intermediate
    leaf_cert
        .verify_signature(Some(&inter_cert.tbs_certificate.subject_pki))
        .context("signature verification failed")?;
    Ok(())
}

pub fn sign_challenge(challenge: &[u8; 32]) -> Signature {
    // Load the private key
    let leaf_key = Ed25519KeyPair::from_pkcs8(MOCK_PRIVATE_KEY_PKCS8).unwrap();
    leaf_key.sign(challenge)
}

pub fn verify_sig(challenge: &[u8; 32], signature: &[u8]) -> Result<()> {
    let pub_key = UnparsedPublicKey::new(&ED25519, MOCK_PUBLIC_KEY);
    pub_key
        .verify(challenge, signature.as_ref())
        .map_err(|_| anyhow!("Sig verification failed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;

    #[test]
    fn test_verify_app_attest() {
        // Verify the attestation
        let result = verify_app_attest(ATTESTATION);
        assert!(
            result.is_ok(),
            "Attestation verification failed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_sign_and_verify_random_challenge() {
        use ring::rand::SecureRandom;

        // Generate a random 32-byte challenge
        let rng = SystemRandom::new();
        let mut challenge = [0u8; 32];
        rng.fill(&mut challenge)
            .expect("Failed to generate random challenge");

        // Sign the challenge
        let signature = sign_challenge(&challenge);

        // Verify the signature
        let result = verify_sig(&challenge, signature.as_ref());
        assert!(
            result.is_ok(),
            "Signature verification failed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_verify_wrong_signature_fails() {
        let challenge: [u8; 32] = [0u8; 32];
        let mut wrong_challenge: [u8; 32] = [0u8; 32];
        wrong_challenge[0] = 1; // Make it different

        // Sign the original challenge
        let signature = sign_challenge(&challenge);

        // Try to verify with wrong challenge - should fail
        let result = verify_sig(&wrong_challenge, signature.as_ref());
        assert!(
            result.is_err(),
            "Verification should fail with wrong challenge"
        );
    }

    #[test]
    fn test_verify_corrupted_signature_fails() {
        let challenge: [u8; 32] = [0u8; 32];

        // Sign the challenge
        let signature = sign_challenge(&challenge);

        // Corrupt the signature
        let mut corrupted_sig = signature.as_ref().to_vec();
        corrupted_sig[0] ^= 0xFF;

        // Verification should fail
        let result = verify_sig(&challenge, &corrupted_sig);
        assert!(
            result.is_err(),
            "Verification should fail with corrupted signature"
        );
    }
}
