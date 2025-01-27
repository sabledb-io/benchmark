use bytes::BytesMut;
use rand::{distr::Alphanumeric, Rng};
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

/// Generate random string of length `len` and in the range of `key_range`
pub fn generate_key(len: usize, key_range: usize) -> BytesMut {
    let number: u64 = if RANDOMIZE_KEYS.load(Ordering::Relaxed) {
        let rnd: u64 = rand::rng().random();
        rnd.rem_euclid(key_range as u64)
    } else {
        let number = COUNTER.fetch_add(1, Ordering::Relaxed);
        if number >= key_range as u64 {
            COUNTER.store(0, Ordering::Relaxed);
        }
        number
    };
    let right_string = BytesMutUtils::from::<u64>(&number);
    let mut left_string = BytesMutUtils::from(&"0".repeat(len.saturating_sub(right_string.len())));
    left_string.extend_from_slice(&right_string);
    left_string
}

pub fn set_randomize_keys(random: bool) {
    RANDOMIZE_KEYS.store(random, Ordering::Relaxed);
}
