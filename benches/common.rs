use hlagg::protocol::{
    ElGamal,
    messages::{AggParams, ClientKey, DecKey},
};
use rand::Rng;
use rand_core::OsRng;
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::OnceLock;

// Setup data structure
#[derive(Clone)]
#[allow(dead_code)]
pub struct SetupData {
    pub params: AggParams,
    pub sk: DecKey,
    pub cks: Vec<ClientKey>,
}

// Global cache for setup data - ensures each configuration is only generated once
static SETUP_CACHE: OnceLock<Mutex<HashMap<(usize, usize, usize), SetupData>>> = OnceLock::new();

// Get setup data for a specific configuration, initializing if needed
#[allow(dead_code)]
pub fn get_setup_data(num_clients: usize, length: usize, bitlength: usize) -> SetupData {
    let cache = SETUP_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut cache = cache.lock().unwrap();

    // Check if we already have this configuration
    match cache.get(&(num_clients, length, bitlength)) {
        Some(cached) => cached.clone(),
        None => {
            let (params, sk, cks) = ElGamal::setup(num_clients, length, &mut OsRng);
            let data = SetupData { params, sk, cks };
            cache.insert((num_clients, length, bitlength), data.clone());
            data
        }
    }
}

#[allow(dead_code)]
pub fn random_inputs(len: usize, bitlength: usize) -> Vec<u64> {
    let mut rng = OsRng;
    (0..len)
        .map(|_| rng.gen_range(0..(1 << bitlength)))
        .collect()
}
