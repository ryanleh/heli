use std::time::Duration;

#[derive(Debug)]
pub struct TimeStats {
    pub mean: Duration,
    pub min: Duration,
    pub max: Duration,
    pub median: Duration,
    pub std_dev: Duration,
}

impl TimeStats {
    pub fn from_times(times: &[Duration]) -> Self {
        if times.is_empty() {
            return Self {
                mean: Duration::ZERO,
                min: Duration::ZERO,
                max: Duration::ZERO,
                median: Duration::ZERO,
                std_dev: Duration::ZERO,
            };
        }

        // Sort times to find min, max, median
        let mut sorted_times = times.to_vec();
        sorted_times.sort();

        let mean_nanos =
            times.iter().map(|d| d.as_nanos() as f64).sum::<f64>() / times.len() as f64;
        let mean = Duration::from_nanos(mean_nanos as u64);
        let min = sorted_times[0];
        let max = sorted_times[times.len() - 1];
        let median = sorted_times[times.len() / 2];

        // Calculate standard deviation
        let variance = times
            .iter()
            .map(|d| {
                let diff = d.as_nanos() as f64 - mean_nanos;
                diff * diff
            })
            .sum::<f64>()
            / times.len() as f64;
        let std_dev = Duration::from_nanos(variance.sqrt() as u64);

        Self {
            mean,
            min,
            max,
            median,
            std_dev,
        }
    }
}

/// Helper function to format duration with 2 decimal places
pub fn format_duration(duration: Duration) -> String {
    let millis = duration.as_micros() as f64 / 1000.0;
    format!("{:.2}ms", millis)
}

/// Print benchmark results in a table format
pub fn print_results(
    results: &[(usize, TimeStats)],
    proof_system_name: &str,
    clients: &[usize],
    length: usize,
    bitlength: usize,
    iterations: usize,
    warmup: usize,
    table_title: &str,
    total_column_name: &str,
    per_item_column_name: &str,
) {
    println!("Configuration:");
    println!("  Proof System: {}", proof_system_name);
    println!("  Client Counts: {:?}", clients);
    println!("  Input Length: {}", length);
    println!("  Bitlength: {}", bitlength);
    println!("  Iterations: {} (warmup: {})", iterations, warmup);

    println!("\n{}:", table_title);
    println!(
        "  Clients | {} | {} | Relative | Median (ms) | Min (ms) | Max (ms) | Std Dev (ms)",
        total_column_name, per_item_column_name
    );
    println!(
        "  --------|{}|{}|----------|-------------|----------|----------|-------------",
        "-".repeat(total_column_name.len() + 2),
        "-".repeat(per_item_column_name.len() + 2)
    );

    // Calculate baseline per-item cost (from first result)
    let baseline_per_item = if let Some((_, first_stats)) = results.first() {
        first_stats.mean / results[0].0 as u32
    } else {
        Duration::ZERO
    };

    for (item_count, stats) in results {
        let per_item = stats.mean / *item_count as u32;

        // Calculate speedup (baseline / current)
        let relative = if baseline_per_item > Duration::ZERO {
            let speedup = baseline_per_item.as_nanos() as f64 / per_item.as_nanos() as f64;
            format!("{:.1}x", speedup)
        } else {
            "1.0x".to_string()
        };

        println!(
            "  {:6} | {:width1$} | {:width2$} | {:8} | {:11} | {:8} | {:8} | {:11}",
            item_count,
            format_duration(stats.mean),
            format_duration(per_item),
            relative,
            format_duration(stats.median),
            format_duration(stats.min),
            format_duration(stats.max),
            format_duration(stats.std_dev),
            width1 = total_column_name.len(),
            width2 = per_item_column_name.len(),
        );
    }
}
