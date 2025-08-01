use crate::Options;
use hdrhistogram::Histogram;
use indicatif::ProgressBar;
use lazy_static::lazy_static;
use serde::Serialize;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Mutex,
};

lazy_static! {
    static ref REQUESTS_PROCESSED: AtomicUsize = AtomicUsize::new(0);
    static ref SETGET_SET_CLIENTS: AtomicUsize = AtomicUsize::new(0);
    static ref SETGET_GET_CLIENTS: AtomicUsize = AtomicUsize::new(0);
    static ref HITS: AtomicUsize = AtomicUsize::new(0);
    static ref RUNNING_THREADS: AtomicUsize = AtomicUsize::new(0);
    // possible values:
    // 100us -> 10 minutes
    static ref HIST: Mutex<Histogram<u64>>
        = Mutex::new(Histogram::<u64>::new_with_bounds(1, 600000000, 2).unwrap());
    static ref PROGRESS: ProgressBar = ProgressBar::new(10);
    static ref JSON_OUTPUT: AtomicBool = AtomicBool::new(false);
}

#[derive(Serialize, Debug, Default)]
pub struct Latency {
    pmin: f64,
    p50: f64,
    p90: f64,
    p95: f64,
    p99: f64,
    p995: f64,
    p999: f64,
    pmax: f64,
}

#[derive(Serialize, Debug, Default)]
pub struct Stats {
    test_duration_secs: usize,
    total_connections: usize,
    total_threads: usize,
    total_requests: usize,
    total_hits: usize,
    key_size: usize,
    value_size: usize,
    rps: usize,
    pipeline: usize,
    latency_ms: Latency,
    options: Options,
}

impl Stats {
    pub fn collect(opts: &Options, test_duration_millis: f64) -> Self {
        let total_connections = opts.connections;
        let total_threads = opts.threads;
        let total_requests = requests_processed();
        let total_hits = total_hits();
        let key_size = opts.get_key_size();
        let value_size = opts.data_size;
        let rps = ((total_requests as f64 / test_duration_millis) * 1000.0) as usize;
        let pipeline = opts.pipeline;
        let mut latency_ms = Latency::default();

        {
            let guard = HIST.lock().expect("lock");
            latency_ms.pmin = guard.min() as f64 / 1000.0;
            latency_ms.p50 = guard.value_at_quantile(0.5) as f64 / 1000.0;
            latency_ms.p90 = guard.value_at_quantile(0.9) as f64 / 1000.0;
            latency_ms.p95 = guard.value_at_quantile(0.95) as f64 / 1000.0;
            latency_ms.p99 = guard.value_at_quantile(0.99) as f64 / 1000.0;
            latency_ms.p995 = guard.value_at_quantile(0.995) as f64 / 1000.0;
            latency_ms.p999 = guard.value_at_quantile(0.999) as f64 / 1000.0;
            latency_ms.pmax = guard.max() as f64 / 1000.0;
        }

        Stats {
            test_duration_secs: (test_duration_millis / 1000.0) as usize,
            total_connections,
            total_threads,
            total_requests,
            total_hits,
            key_size,
            value_size,
            rps,
            pipeline,
            latency_ms,
            options: opts.clone(),
        }
    }
}

pub fn is_json_output() -> bool {
    JSON_OUTPUT.load(Ordering::Relaxed)
}

pub fn set_use_json_output(b: bool) {
    JSON_OUTPUT.store(b, Ordering::Relaxed)
}

/// Increment the total number of requests by `count`
pub fn incr_requests(count: usize) {
    REQUESTS_PROCESSED.fetch_add(count, Ordering::Relaxed);
    if !is_json_output() {
        PROGRESS.inc(count as u64);
    }
}

/// Increment the total number of requests by 1
pub fn incr_hits() {
    HITS.fetch_add(1, Ordering::Relaxed);
}

/// Return the total requests processed
pub fn requests_processed() -> usize {
    REQUESTS_PROCESSED.load(Ordering::Relaxed)
}

/// Return the total hits
pub fn total_hits() -> usize {
    HITS.load(Ordering::Relaxed)
}

/// Increment the number of running threads by 1
pub fn incr_threads_running() {
    RUNNING_THREADS.fetch_add(1, Ordering::Relaxed);
}

/// Reduce the number of running threads by 1
pub fn decr_threads_running() {
    RUNNING_THREADS.fetch_sub(1, Ordering::Relaxed);
}

pub fn record_latency(val: u64) {
    let mut guard = HIST.lock().expect("lock");
    if let Err(e) = guard.record(val) {
        tracing::error!("Failed to record histogram. {:?}", e);
    }
}

pub fn print_latency() {
    let guard = HIST.lock().expect("lock");
    if !is_json_output() {
        println!(
            r#"    Latency: [min: {}ms, p50: {}ms, p90: {}ms, p95: {}ms, p99: {}ms, p99.5: {}ms, p99.9: {}ms, max: {}ms]"#,
            guard.min() as f64 / 1000.0,
            guard.value_at_quantile(0.5) as f64 / 1000.0,
            guard.value_at_quantile(0.9) as f64 / 1000.0,
            guard.value_at_quantile(0.95) as f64 / 1000.0,
            guard.value_at_quantile(0.99) as f64 / 1000.0,
            guard.value_at_quantile(0.995) as f64 / 1000.0,
            guard.value_at_quantile(0.999) as f64 / 1000.0,
            guard.max() as f64 / 1000.0,
        );
    }
}

pub fn finish_progress() {
    if !is_json_output() {
        PROGRESS.finish();
    }
}

pub fn finalise_progress_setup(len: u64) {
    if !is_json_output() {
        PROGRESS.set_length(len);
        PROGRESS.set_style(
        indicatif::ProgressStyle::with_template(
            "{spinner:.red} [Progress: {percent}%] {wide_bar:.green/green } [{elapsed_precise}] ({eta})",
        )
        .expect("finalise_progress"),
    );
    }
}

pub fn incr_setget_set_tasks(count: usize) {
    SETGET_SET_CLIENTS.fetch_add(count, Ordering::Relaxed);
}

pub fn incr_setget_get_tasks(count: usize) {
    SETGET_GET_CLIENTS.fetch_add(count, Ordering::Relaxed);
}

/// Return the number SET tasks launched when the "setget" test was selected
pub fn setget_set_tasks() -> usize {
    SETGET_SET_CLIENTS.load(Ordering::Relaxed)
}

/// Return the number GET tasks launched when the "setget" test was selected
pub fn setget_get_tasks() -> usize {
    SETGET_GET_CLIENTS.load(Ordering::Relaxed)
}
