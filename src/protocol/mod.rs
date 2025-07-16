/// Hardcoded group
pub type G = curve25519_dalek::RistrettoPoint;
pub type Scalar = curve25519_dalek::Scalar;

pub mod elgamal;
pub use elgamal::*;

pub mod messages;

pub mod provers;
pub use provers::*;
