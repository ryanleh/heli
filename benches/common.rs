use hlagg::protocol::serialization::ToBytes;
use rand::Rng;
use rand_core::OsRng;

/// Generate a random binary vector of the given length.
pub fn random_binary_vec(len: usize) -> Vec<u32> {
    let mut rng = OsRng;
    (0..len)
        .map(|_| if rng.gen_bool(0.5) { 1 } else { 0 })
        .collect()
}

/// Return the serialized size (in bytes) of an item implementing ToBytes.
pub fn serialized_size<T: ToBytes>(item: &T) -> usize {
    item.to_bytes().len()
}

/// Generate random binary input vectors for multiple clients.
pub fn random_inputs(num_clients: usize, length: usize) -> Vec<Vec<u32>> {
    (0..num_clients)
        .map(|_| random_binary_vec(length))
        .collect()
}
