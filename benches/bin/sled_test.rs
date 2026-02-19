use sled::{Batch, Config, Mode};
use std::env;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Barrier,
};
use std::thread;
use std::time::{Duration, Instant};

fn parse_arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

// Small fast PRNG (SplitMix64). Good enough for benchmarking.
#[derive(Clone)]
struct SplitMix64 {
    x: u64,
}
impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { x: seed }
    }
    fn next_u64(&mut self) -> u64 {
        let mut z = {
            self.x = self.x.wrapping_add(0x9E3779B97F4A7C15);
            self.x
        };
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn fill_bytes(&mut self, buf: &mut [u8]) {
        let mut i = 0;
        while i < buf.len() {
            let r = self.next_u64().to_le_bytes();
            let n = (buf.len() - i).min(8);
            buf[i..i + n].copy_from_slice(&r[..n]);
            i += n;
        }
    }
}

fn main() -> anyhow::Result<()> {
    // ---- Defaults ----
    let args: Vec<String> = env::args().collect();
    let path = parse_arg(&args, "--path").unwrap_or_else(|| "./sled_bench_db".to_string());
    let threads: usize = parse_arg(&args, "--threads")
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| {
            thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(8)
        });
    let duration_s: u64 = parse_arg(&args, "--seconds")
        .and_then(|s| s.parse().ok())
        .unwrap_or(15);

    // How much payload (approx) to put in each apply_batch call.
    // This is a *target*; actual bytes written differs due to overhead.
    let batch_bytes_target: usize = parse_arg(&args, "--batch-bytes")
        .and_then(|s| s.parse().ok())
        .unwrap_or(8 * 1024 * 1024); // 8 MiB

    let key_size: usize = parse_arg(&args, "--key-bytes")
        .and_then(|s| s.parse().ok())
        .unwrap_or(16);

    let val_size: usize = parse_arg(&args, "--value-bytes")
        .and_then(|s| s.parse().ok())
        .unwrap_or(256);

    let flush_every_ms: u64 = parse_arg(&args, "--flush-every-ms")
        .and_then(|s| s.parse().ok())
        .unwrap_or(2000);

    let random_values = has_flag(&args, "--random-values");

    eprintln!("sled throughput bench");
    eprintln!("  path            = {}", path);
    eprintln!("  threads         = {}", threads);
    eprintln!("  duration        = {}s", duration_s);
    eprintln!("  batch_bytes     = {}", batch_bytes_target);
    eprintln!("  key_bytes       = {}", key_size);
    eprintln!("  value_bytes     = {}", val_size);
    eprintln!("  flush_every_ms  = {}", flush_every_ms);
    eprintln!("  random_values   = {}", random_values);
    eprintln!();

    // ---- DB open (HighThroughput + flush tuning) ----
    let db = Config::default()
        .path(&path)
        .mode(Mode::HighThroughput)
        .flush_every_ms(Some(flush_every_ms))
        .open()?;

    let tree = Arc::new(db.open_tree("t")?);

    // ---- Shared counters ----
    let stop = Arc::new(AtomicBool::new(false));
    let total_payload = Arc::new(AtomicU64::new(0)); // (key+value) bytes enqueued
    let total_ops = Arc::new(AtomicU64::new(0));

    let barrier = Arc::new(Barrier::new(threads + 1));
    let mut handles = Vec::with_capacity(threads);

    for tid in 0..threads {
        let tree = tree.clone();
        let stop = stop.clone();
        let total_payload = total_payload.clone();
        let total_ops = total_ops.clone();
        let barrier = barrier.clone();

        handles.push(thread::spawn(move || {
            // Each thread writes to its own shard prefix -> reduces contention.
            // Key format: [tid (u32)] [counter (u64)] [padding...]
            let mut counter: u64 = 0;
            let tid_u32 = tid as u32;

            let mut rng = SplitMix64::new(0xD1B54A32D192ED03u64 ^ (tid as u64).wrapping_mul(0x9E37));

            // Pre-build a constant value if random_values=false (lowest CPU).
            let mut const_val = vec![0u8; val_size];
            if !random_values {
                // Fill with deterministic pattern so it's not all zeros.
                rng.fill_bytes(&mut const_val);
            }

            barrier.wait(); // synchronize start

            while !stop.load(Ordering::Relaxed) {
                let mut batch = Batch::default();
                let mut approx_bytes = 0usize;
                let mut ops = 0u64;

                while approx_bytes < batch_bytes_target && !stop.load(Ordering::Relaxed) {
                    let mut key = vec![0u8; key_size];

                    // tid prefix
                    key[0..4].copy_from_slice(&tid_u32.to_le_bytes());

                    // counter
                    let c_bytes = counter.to_le_bytes();
                    let c_off = 4;
                    let c_end = (c_off + 8).min(key.len());
                    if c_end > c_off {
                        key[c_off..c_end].copy_from_slice(&c_bytes[..(c_end - c_off)]);
                    }

                    // pad rest (optional) for wider keys
                    if key.len() > 12 {
                        let mut pad_rng = rng.clone();
                        pad_rng.fill_bytes(&mut key[12..]);
                    }

                    let value = if random_values {
                        let mut v = vec![0u8; val_size];
                        rng.fill_bytes(&mut v);
                        v
                    } else {
                        const_val.clone()
                    };

                    batch.insert(key, value);

                    counter = counter.wrapping_add(1);
                    ops += 1;
                    approx_bytes += key_size + val_size;
                }

                // Apply this batch
                tree.apply_batch(batch).expect("apply_batch failed");

                total_ops.fetch_add(ops, Ordering::Relaxed);
                total_payload.fetch_add(approx_bytes as u64, Ordering::Relaxed);
            }
        }));
    }

    // ---- Run ----
    barrier.wait();
    let start = Instant::now();
    let deadline = start + Duration::from_secs(duration_s);

    while Instant::now() < deadline {
        thread::sleep(Duration::from_millis(500));
    }
    stop.store(true, Ordering::Relaxed);

    for h in handles {
        let _ = h.join();
    }

    // Optional: flush at end to force durability
    // db.flush()?; // uncomment if you want “after-flush” results

    let elapsed = start.elapsed().as_secs_f64();
    let ops = total_ops.load(Ordering::Relaxed) as f64;
    let payload = total_payload.load(Ordering::Relaxed) as f64;

    let mb = payload / (1024.0 * 1024.0);
    let mbps = mb / elapsed;
    let ops_s = ops / elapsed;

    println!("elapsed: {:.3}s", elapsed);
    println!("ops:     {:.0} ({:.0} ops/s)", ops, ops_s);
    println!("payload: {:.1} MiB ({:.1} MiB/s)", mb, mbps);
    println!();
    println!("Note: 'payload' counts (key+value) bytes submitted, not on-disk bytes.");
    println!("      On-disk usage will differ due to internal overhead / compaction.");
    Ok(())
}

