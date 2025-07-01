use serde::Deserialize;
use std::fs::File;
use std::path::PathBuf;
use tracing::info;
use tracing_appender;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt}; // TODO

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct Config {
    pub network: NetworkConfig,
    pub protocol: ProtocolConfig,
    pub logging: LoggingConfig,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct NetworkConfig {
    pub decryptor_addr: String,
    pub aggregator_addr: String,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct ProtocolConfig {
    pub num_clients: usize,
    pub length: usize,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct LoggingConfig {
    pub name: String,
    pub level: String,
}

impl Config {
    /// Load configuration from a TOML file
    pub fn from_file(path: &PathBuf) -> anyhow::Result<Self> {
        let config_content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&config_content)?;
        Ok(config)
    }

    /// Setup logging based on configuration
    pub fn setup_logging(&self, party_suffix: &str) -> WorkerGuard {
        // Create log directory
        let exe_path = std::env::current_exe().unwrap();
        let project_root = exe_path
            .parent() // release/
            .and_then(|p| p.parent()) // target/
            .and_then(|p| p.parent()) // project root
            .expect("Failed to resolve project root");
        let mut log_path = project_root.join("experiments/logs");
        std::fs::create_dir_all(&log_path).expect("Failed to create logs directory");

        // Create party-specific log file
        log_path.push(format!("{}.{}", self.logging.name, party_suffix));
        let file = File::create(log_path).expect("Could not create log file");
        let (file_writer, file_guard) = tracing_appender::non_blocking(file);

        // File logging layer
        //
        // TODO: Have this leave a time-specific log
        let file_layer = fmt::layer().with_writer(file_writer).with_ansi(false);

        // stdout logging layer
        let stdout_layer = fmt::layer().with_writer(std::io::stdout).with_ansi(true);

        tracing_subscriber::registry()
            .with(EnvFilter::new(self.logging.level.as_str()))
            .with(stdout_layer)
            .with(file_layer)
            .init();

        // This needs to stay alive to ensure the file is logged too
        file_guard
    }

    /// Log startup information
    pub fn log_startup(&self, component: &str, config_path: &PathBuf) {
        info!("Starting {} with config: {:?}", component, config_path);
    }
}
