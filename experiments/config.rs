use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExperimentConfig {
    /// Number of clients to simulate
    pub num_clients: usize,

    /// Minimum number of clients required for aggregation
    pub threshold: usize,

    /// Number of clients to randomly exclude from report submission
    pub dropouts: usize,

    /// Number of data slots per client
    pub length: usize,

    /// Prover configuration
    pub prover: ProverConfig,

    /// Aggregator network address
    pub aggregator_addr: String,

    /// Decryptor network address
    pub decryptor_addr: String,

    /// Path to the sled database
    pub db_path: String,

    /// Max in-flight chunks on the aggregator before backpressure kicks in (default: 4)
    #[serde(default = "default_max_pending_batches")]
    pub max_pending_batches: usize,

    /// Number of reports to accumulate into a single processing chunk (default: 10000)
    #[serde(default = "default_reports_per_chunk")]
    pub reports_per_chunk: usize,
}

fn default_max_pending_batches() -> usize {
    4
}

fn default_reports_per_chunk() -> usize {
    10_000
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ProverConfig {
    #[serde(rename = "binary")]
    Binary,
    #[serde(rename = "range")]
    Range { bitlength: usize },
}

impl ProverConfig {
    #[allow(dead_code)]
    pub fn to_prover_type(&self) -> heli::system::ProverType {
        match self {
            ProverConfig::Binary => heli::system::ProverType::Binary,
            ProverConfig::Range { bitlength } => heli::system::ProverType::Range(*bitlength),
        }
    }
}

impl ExperimentConfig {
    /// Load config from a JSON file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let contents = fs::read_to_string(path)?;
        let config: ExperimentConfig = serde_json::from_str(&contents)?;
        Ok(config)
    }
}
