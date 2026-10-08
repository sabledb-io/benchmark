use bytes::BytesMut;
use rand::{
    distr::{Alphanumeric, Uniform},
    RngExt,
};
use sbcommonlib::BytesMutUtils;
use std::sync::atomic::Ordering;
use std::sync::atomic::{AtomicBool, AtomicU64};

lazy_static::lazy_static! {
    static ref COUNTER: AtomicU64 = AtomicU64::default();
    static ref RANDOMIZE_KEYS: AtomicBool = AtomicBool::default();
}

/// Generate random string of length `len`
pub fn generate_payload(len: usize) -> BytesMut {
    let s: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect();
    BytesMutUtils::from_string(&s)
}

/// The source of the values used by the write tests
pub enum ValueSource {
    /// Use the same random payload for every command
    Fixed(BytesMut),
    /// Pick a random value from the dataset for every command
    Dataset(&'static crate::dataset::Dataset),
}

impl ValueSource {
    /// Use the loaded dataset if there is one, otherwise a random payload of `len` bytes
    pub fn new(len: usize) -> Self {
        match crate::dataset::get() {
            Some(ds) => ValueSource::Dataset(ds),
            None => ValueSource::Fixed(generate_payload(len)),
        }
    }

    #[inline]
    pub fn next_value(&self) -> &[u8] {
        match self {
            ValueSource::Fixed(payload) => payload,
            ValueSource::Dataset(ds) => ds.random_value(),
        }
    }
}

/// Reserve a block of `count` sequential key IDs using a single atomic
/// operation, returning the first ID in the block. Callers pass the returned
/// `start_id` to [`write_key`] along with the per-key offset within the batch.
///
/// This replaces the previous one-atomic-per-key scheme with one atomic per
/// pipeline batch.
pub fn reserve_sequential_ids(count: usize) -> u64 {
    COUNTER.fetch_add(count as u64, Ordering::Relaxed)
}

/// Write a benchmark key of width `len` into `out`, reusing its storage.
///
/// `out` is cleared first so a single `BytesMut` can be reused across the whole
/// benchmark loop. For sequential keys the generated number is
/// `(start_id + index) % key_range`, preserving the previous zero-padding and
/// key-range wrapping behaviour. When random keys are enabled, a random number
/// in `[0, key_range)` is used and `start_id`/`index` are ignored.
pub fn write_key(out: &mut BytesMut, len: usize, key_range: usize, start_id: u64, index: usize) {
    // Guard against a zero key-range to avoid a divide-by-zero; in practice the
    // key range is always >= 1.
    let modulo = (key_range as u64).max(1);
    let number: u64 = if RANDOMIZE_KEYS.load(Ordering::Relaxed) {
        let rnd: u64 = rand::rng().random();
        rnd.rem_euclid(modulo)
    } else {
        start_id.wrapping_add(index as u64) % modulo
    };

    out.clear();
    let mut tmp = [0u8; sbcommonlib::MAX_U64_DECIMAL_DIGITS];
    let digits = sbcommonlib::encode_u64_decimal(number, &mut tmp);
    let pad = len.saturating_sub(digits.len());
    out.reserve(pad + digits.len());
    for _ in 0..pad {
        out.extend_from_slice(b"0");
    }
    out.extend_from_slice(digits);
}

/// Limits the request rate of a single connection ("task").
/// The global `--limit-rps` is divided equally between all connections.
pub struct RateLimiter {
    /// Time between two batches. `None` means no limit
    interval: Option<std::time::Duration>,
    next: tokio::time::Instant,
}

impl RateLimiter {
    pub fn new(opts: &crate::sb_options::Options) -> Self {
        let interval = opts.limit_rps.map(|rps| {
            let per_task_rps = (rps as f64 / opts.connections as f64).max(f64::MIN_POSITIVE);
            std::time::Duration::try_from_secs_f64(opts.pipeline as f64 / per_task_rps)
                .unwrap_or(std::time::Duration::MAX)
        });
        Self {
            interval,
            next: tokio::time::Instant::now(),
        }
    }

    /// Wait until the next batch is allowed. Call this before starting the timer
    pub async fn wait(&mut self) {
        let Some(interval) = self.interval else {
            return;
        };
        let now = tokio::time::Instant::now();
        // Do not try to catch up after a slow response
        if self.next < now {
            self.next = now;
        }
        let deadline = self.next;
        self.next = self.next.checked_add(interval).unwrap_or(now);
        tokio::time::sleep_until(deadline).await;
    }
}

pub fn set_randomize_keys(random: bool) {
    RANDOMIZE_KEYS.store(random, Ordering::Relaxed);
}

/// Generate random vector of `f32`.
pub fn generate_vector(dim: usize) -> String {
    let range = Uniform::new(0f32, f32::MAX).expect("Failed to create number Uniform");
    let v: Vec<f32> = rand::rng().sample_iter(range).take(dim).collect();
    vector_to_hex_string(&v)
}

fn vector_to_hex_string(numbers: &[f32]) -> String {
    let bytes: Vec<u8> = numbers
        .iter()
        .flat_map(|&float| float.to_le_bytes().to_vec())
        .collect();

    hex::encode(&bytes)
        .as_bytes()
        .chunks(2)
        .fold(String::new(), |acc, chunk| {
            let s = std::str::from_utf8(chunk).unwrap();
            acc + &format!("\\x{}", s)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vector_generation() {
        let v: Vec<f32> = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let s = vector_to_hex_string(&v);
        assert_eq!(s, "\\x00\\x00\\x80\\x3f\\x00\\x00\\x00\\x40\\x00\\x00\\x40\\x40\\x00\\x00\\x80\\x40\\x00\\x00\\xa0\\x40");
    }

    #[test]
    fn test_write_key_zero_padding() {
        set_randomize_keys(false);
        let mut key = BytesMut::new();
        write_key(&mut key, 6, 1_000_000, 42, 0);
        assert_eq!(&key[..], b"000042");
    }

    #[test]
    fn test_write_key_uses_start_id_and_index() {
        set_randomize_keys(false);
        let mut key = BytesMut::new();
        write_key(&mut key, 4, 1_000_000, 100, 5);
        assert_eq!(&key[..], b"0105");
    }

    #[test]
    fn test_write_key_wraps_on_key_range() {
        set_randomize_keys(false);
        let mut key = BytesMut::new();
        // (999 + 3) % 1000 == 2
        write_key(&mut key, 4, 1000, 999, 3);
        assert_eq!(&key[..], b"0002");
    }

    #[test]
    fn test_write_key_no_truncation_when_number_wider_than_len() {
        set_randomize_keys(false);
        let mut key = BytesMut::new();
        write_key(&mut key, 2, 1_000_000, 123_456, 0);
        assert_eq!(&key[..], b"123456");
    }

    #[test]
    fn test_write_key_reuses_buffer_across_calls() {
        set_randomize_keys(false);
        let mut key = BytesMut::new();
        write_key(&mut key, 4, 1000, 1, 0);
        write_key(&mut key, 4, 1000, 2, 0);
        // The second call must clear the first key's contents.
        assert_eq!(&key[..], b"0002");
    }

    #[test]
    fn test_reserve_sequential_ids_allocates_contiguous_blocks() {
        let first = reserve_sequential_ids(5);
        let second = reserve_sequential_ids(3);
        // A batch of 5 IDs must be reserved before the next block starts.
        assert_eq!(second, first + 5);
    }
}
