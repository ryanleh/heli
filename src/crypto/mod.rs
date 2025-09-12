/// Hardcoded group types
pub type G = curve25519_dalek::RistrettoPoint;
pub type Scalar = curve25519_dalek::Scalar;

/// ElGamal linearly-homomorphic vector encryption scheme
pub mod elgamal;
pub use elgamal::*;

/// Two different PRFs:
/// * AES-based PRF for generating random scalar elements,
/// * Naor-Pinkas-Reingold key-homomorphic PRF
pub mod prf;
pub use prf::*;
