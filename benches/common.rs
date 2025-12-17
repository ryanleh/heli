use heli::agg_only_enc::{AggOnlyEnc, EvalKey, SecretKey};
use rand::Rng;
use rand_core::OsRng;
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::OnceLock;

// Setup data structure
#[allow(dead_code)]
pub struct SetupData {
    pub sk: SecretKey,
    pub eval_keys: Vec<EvalKey>,
}

// Global cache for setup data - ensures each configuration is only generated once
static SETUP_CACHE: OnceLock<Mutex<HashMap<(usize, usize, usize), SetupData>>> = OnceLock::new();

// Get setup data for a specific configuration, initializing if needed
#[allow(dead_code)]
pub fn get_setup_data(num_clients: usize, length: usize, bitlength: usize) -> SetupData {
    let cache = SETUP_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut cache = cache.lock().unwrap();

    // Check if we already have this configuration
    // Note: We can't cache SetupData because SecretKey doesn't implement Clone
    // So we always generate fresh setup data
    let (sk, eval_keys) = AggOnlyEnc::setup(num_clients, &mut OsRng);
    SetupData { sk, eval_keys }
}

#[allow(dead_code)]
pub fn random_inputs(len: usize, bitlength: usize) -> Vec<u64> {
    let mut rng = OsRng;
    (0..len)
        .map(|_| rng.gen_range(0..(1 << bitlength)))
        .collect()
}
