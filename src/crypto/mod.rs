/// Hardcoded group types
pub type G = curve25519_dalek::RistrettoPoint;
pub type Scalar = curve25519_dalek::Scalar;

/// Algorithms for solving discrete-log
pub mod dlog;
pub use dlog::*;

/// Two different PRFs:
/// * AES-based PRF for generating random scalar elements,
/// * Naor-Pinkas-Reingold key-homomorphic PRF
pub mod prf;
pub use prf::*;

/// HPKE encryption / decryption algorithms
pub mod hpke;
pub use hpke::*;

// Code for mocking apple app attest verification
pub mod app_attest;
pub use app_attest::*;
