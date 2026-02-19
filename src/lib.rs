#![deny(unused_import_braces, unused_qualifications, trivial_casts)]
#![deny(trivial_numeric_casts, variant_size_differences)]
#![deny(stable_features, unreachable_pub, non_shorthand_field_patterns)]
#![deny(unused_attributes, unused_mut)]
#![deny(unused_imports)]
#![deny(renamed_and_removed_lints, stable_features, unused_allocation)]
#![deny(unused_comparisons, bare_trait_objects, unused_must_use)]
#![forbid(unsafe_code)]

/// Number of unique reports generated in simulated mode.
pub const BATCH_REPORT_SIZE: usize = 1024;

/// Compact 3-byte client index, supporting up to 16,777,215 clients.
/// Uses little-endian encoding of the lower 24 bits of a u32.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ClientIndex(pub [u8; 3]);

impl From<u32> for ClientIndex {
    #[inline]
    fn from(val: u32) -> Self {
        Self([val as u8, (val >> 8) as u8, (val >> 16) as u8])
    }
}

impl From<usize> for ClientIndex {
    #[inline]
    fn from(val: usize) -> Self {
        Self::from(val as u32)
    }
}

impl From<ClientIndex> for u32 {
    #[inline]
    fn from(idx: ClientIndex) -> u32 {
        idx.0[0] as u32 | ((idx.0[1] as u32) << 8) | ((idx.0[2] as u32) << 16)
    }
}

impl From<ClientIndex> for u64 {
    #[inline]
    fn from(idx: ClientIndex) -> u64 {
        u32::from(idx) as u64
    }
}

impl From<ClientIndex> for usize {
    #[inline]
    fn from(idx: ClientIndex) -> usize {
        u32::from(idx) as usize
    }
}

/// Crypto primitives: ElGamal encryption, PRFs
pub mod crypto;

/// Aggregation-only encryption scheme
pub mod agg_only_enc;

/// Proofs for protecting against malicious clients
pub mod proofs;

/// Heli system
pub mod system;
