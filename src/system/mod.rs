/// Heli system implementation
///
/// TODO: Some of the code here (e.g., Setup) doesn't use the primitive API
pub mod aggregator;
pub mod client;
pub mod decryptor;
pub mod messages;

pub use aggregator::*;
pub use client::*;
pub use decryptor::*;
pub use messages::{bytes_recv, bytes_sent, reset_byte_counters, take_byte_counters};

#[derive(Clone, Copy)]
pub enum ProverType {
    Binary,
    Range(usize), // Bitlength
}

#[cfg(test)]
mod tests;
