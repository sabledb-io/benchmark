use crate::Options;
use hdrhistogram::Histogram;
use indicatif::ProgressBar;
use lazy_static::lazy_static;
use serde::Serialize;
use std::cell::RefCell;
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
    // Global merge targets for the per-run payload-size distributions. Worker
    // threads record into their thread-local histograms (lock-free) and merge
    // into these exactly once, mirroring the latency `HIST` design.
    static ref SENT_SIZES: Mutex<Histogram<u64>> = Mutex::new(new_size_histogram());
    static ref RECV_SIZES: Mutex<Histogram<u64>> = Mutex::new(new_size_histogram());
    static ref PROGRESS: ProgressBar = ProgressBar::new(10);
    static ref JSON_OUTPUT: AtomicBool = AtomicBool::new(false);
}

/// Byte-size histogram spanning 0 bytes up to 4 GiB with 2 significant figures.
/// Zero-length values are valid samples and land in the first bucket.
fn new_size_histogram() -> Histogram<u64> {
    Histogram::<u64>::new_with_bounds(1, 1 << 32, 2).expect("size histogram")
}

thread_local! {
    /// Per-OS-thread latency histogram. Latencies are recorded here lock-free
    /// during the benchmark and merged into the global [`HIST`] exactly once per
    /// worker thread (see [`merge_thread_latency`]) before the thread exits.
    static LOCAL_HIST: RefCell<Histogram<u64>> =
        RefCell::new(Histogram::<u64>::new_with_bounds(1, 600000000, 2).unwrap());

    /// Per-OS-thread payload-size histograms. `SENT` collects the sizes of the
    /// values written during the run; `RECV` collects the sizes of the string
    /// values read back. Both are merged into the globals via
    /// [`merge_thread_sizes`] before the worker thread exits.
    static LOCAL_SENT_SIZES: RefCell<Histogram<u64>> = RefCell::new(new_size_histogram());
    static LOCAL_RECV_SIZES: RefCell<Histogram<u64>> = RefCell::new(new_size_histogram());
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
    /// Distribution of the value sizes actually written during the run.
    /// `None` (and omitted from JSON) when no values were written.
    #[serde(skip_serializing_if = "Option::is_none")]
    sent_value_size: Option<crate::dataset::SizeStats>,
    /// Distribution of the string value sizes read back during the run.
    /// `None` (and omitted from JSON) when no values were read.
    #[serde(skip_serializing_if = "Option::is_none")]
    received_value_size: Option<crate::dataset::SizeStats>,
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
        let sent_value_size = sent_size_stats();
        let received_value_size = received_size_stats();
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
            sent_value_size,
            received_value_size,
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

/// Increment the total number of hits by `count`
pub fn incr_hits(count: usize) {
    if count != 0 {
        HITS.fetch_add(count, Ordering::Relaxed);
    }
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
    LOCAL_HIST.with(|h| {
        if let Err(e) = h.borrow_mut().record(val) {
            tracing::error!("Failed to record histogram. {:?}", e);
        }
    });
}

/// Merge the calling OS thread's local latency histogram into the global
/// aggregate. Call this exactly once per worker thread after its `LocalSet`
/// has finished and before the thread exits.
pub fn merge_thread_latency() {
    LOCAL_HIST.with(|local| {
        let local = local.borrow();
        let mut guard = HIST.lock().expect("lock");
        if let Err(e) = guard.add(&*local) {
            tracing::error!("Failed to merge thread histogram. {:?}", e);
        }
    });
}

/// Record the byte size of a value written to the server.
pub fn record_sent_size(size: u64) {
    LOCAL_SENT_SIZES.with(|h| {
        if let Err(e) = h.borrow_mut().record(size) {
            tracing::error!("Failed to record sent size. {:?}", e);
        }
    });
}

/// Record the byte size of a string value read back from the server. A
/// zero-length value is a valid sample; callers must skip misses (null).
pub fn record_received_size(size: u64) {
    LOCAL_RECV_SIZES.with(|h| {
        if let Err(e) = h.borrow_mut().record(size) {
            tracing::error!("Failed to record received size. {:?}", e);
        }
    });
}

/// Merge the calling OS thread's local sent/received size histograms into the
/// global aggregates. Call this exactly once per worker thread, alongside
/// [`merge_thread_latency`], before the thread exits.
pub fn merge_thread_sizes() {
    LOCAL_SENT_SIZES.with(|local| {
        let local = local.borrow();
        let mut guard = SENT_SIZES.lock().expect("lock");
        if let Err(e) = guard.add(&*local) {
            tracing::error!("Failed to merge sent-size histogram. {:?}", e);
        }
    });
    LOCAL_RECV_SIZES.with(|local| {
        let local = local.borrow();
        let mut guard = RECV_SIZES.lock().expect("lock");
        if let Err(e) = guard.add(&*local) {
            tracing::error!("Failed to merge received-size histogram. {:?}", e);
        }
    });
}

/// Distribution of value sizes written during the run, or `None` if none.
pub fn sent_size_stats() -> Option<crate::dataset::SizeStats> {
    size_stats_from_hist(&SENT_SIZES.lock().expect("lock"))
}

/// Distribution of string value sizes read during the run, or `None` if none.
pub fn received_size_stats() -> Option<crate::dataset::SizeStats> {
    size_stats_from_hist(&RECV_SIZES.lock().expect("lock"))
}

/// Build a [`SizeStats`](crate::dataset::SizeStats) summary from a byte-size
/// histogram, or `None` when nothing was recorded.
fn size_stats_from_hist(hist: &Histogram<u64>) -> Option<crate::dataset::SizeStats> {
    if hist.is_empty() {
        return None;
    }
    let count = hist.len() as usize;
    let avg = hist.mean().round() as usize;
    Some(crate::dataset::SizeStats {
        count,
        total: (hist.mean() * hist.len() as f64).round() as usize,
        avg,
        min: hist.min() as usize,
        p50: hist.value_at_quantile(0.5) as usize,
        p90: hist.value_at_quantile(0.9) as usize,
        p99: hist.value_at_quantile(0.99) as usize,
        max: hist.max() as usize,
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_size_stats_from_empty_hist_is_none() {
        assert!(size_stats_from_hist(&new_size_histogram()).is_none());
    }

    #[test]
    fn test_size_stats_from_hist_records_zero_length() {
        let mut hist = new_size_histogram();
        // A zero-length value is a real sample and must be counted.
        hist.record(0).expect("record 0");
        hist.record(100).expect("record 100");
        hist.record(200).expect("record 200");

        let st = size_stats_from_hist(&hist).expect("stats");
        assert_eq!(st.count, 3);
        assert_eq!(st.min, 0);
        // 2 significant figures => within ~1% of the true max.
        assert!((198..=202).contains(&st.max), "max was {}", st.max);
    }
}
