use crate::valkey_client::{Connection, ValkeyClient};
use crate::{bench_utils, sb_options as options, sb_options::Options, stats};
use bytes::BytesMut;
use sbcommonlib::{stopwatch::StopWatch, ValkeyObject};
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;

#[derive(Error, Debug)]
enum BenchmarkError {
    #[error("I/O error. {0}")]
    StdIoError(#[from] std::io::Error),
    #[error("{0}")]
    UnexpectedResponse(String),
}

/// Expect that `response` is `OK` or return an error
#[inline]
fn expect_ok(response: &ValkeyObject) -> Result<(), BenchmarkError> {
    let status_ok = ValkeyObject::Status("OK".into());
    if !response.eq(&status_ok) {
        return Err(BenchmarkError::UnexpectedResponse(format!(
            "Expected 'OK'. Got: {:?}",
            response
        )));
    }
    Ok(())
}

/// Expect that `response` is `OK` or return an error
#[inline]
fn expect_ok_or_error_contains(response: &ValkeyObject, what: &str) -> Result<(), BenchmarkError> {
    let status_ok = BytesMut::from("OK");
    match response {
        ValkeyObject::Status(status) if status.eq(&status_ok) => Ok(()),
        ValkeyObject::Error(err) => {
            let s = String::from_utf8_lossy(err).to_string();
            if s.contains(what) {
                Ok(())
            } else {
                Err(BenchmarkError::UnexpectedResponse(format!(
                    "Expected 'OK'. Got: {}",
                    s
                )))
            }
        }
        _ => Err(BenchmarkError::UnexpectedResponse(format!(
            "Expected 'OK'. Got: {:?}",
            response
        ))),
    }
}

/// Expect that `response` is `OK` or return an error
#[inline]
fn expect_pong(response: &ValkeyObject) -> Result<(), BenchmarkError> {
    let status_pong = ValkeyObject::Status("PONG".into());
    if !response.eq(&status_pong) {
        return Err(BenchmarkError::UnexpectedResponse(format!(
            "Expected 'PONG'. Got: {:?}",
            response
        )));
    }
    Ok(())
}

/// Expect that `response` is either a String or Null. If it is a string, return `true`, otherwise `false`.
/// If it is neither, return `Err(BenchmarkError)`
#[inline]
fn expect_string_or_null(response: &ValkeyObject) -> Result<bool, BenchmarkError> {
    match response {
        ValkeyObject::NullString => Ok(false),
        ValkeyObject::Str(_value) => Ok(true),

        other => Err(BenchmarkError::UnexpectedResponse(format!(
            "Expected String or Null string. Got: {:?}",
            other
        ))),
    }
}

/// Expect that `response` is either a Integer or Null. If it is an Integer, return `true`, otherwise `false`.
/// If it is neither, return `Err(BenchmarkError)`
#[inline]
fn expect_integer_or_null(response: &ValkeyObject) -> Result<bool, BenchmarkError> {
    match response {
        ValkeyObject::NullString => Ok(false),
        ValkeyObject::Integer(_) => Ok(true),

        other => Err(BenchmarkError::UnexpectedResponse(format!(
            "Expected Integer or Null string. Got: {:?}",
            other
        ))),
    }
}

/// Expect that `response` is either an Integer
#[inline]
fn expect_integer(response: &ValkeyObject) -> Result<(), BenchmarkError> {
    match response {
        ValkeyObject::Integer(_) => Ok(()),
        other => Err(BenchmarkError::UnexpectedResponse(format!(
            "Expected Integer. Got: {:?}",
            other
        ))),
    }
}

/// Expect that `response` to be an array of a given size.
#[inline]
fn expect_array_of_size(response: &ValkeyObject, size: usize) -> Result<bool, BenchmarkError> {
    match response {
        ValkeyObject::Array(arr) if arr.len().eq(&size) => Ok(true),
        ValkeyObject::Array(arr) => {
            return Err(BenchmarkError::UnexpectedResponse(format!(
                "Expected Array of size {}. Got: Array of size: {}",
                size,
                arr.len(),
            )));
        }
        other => Err(BenchmarkError::UnexpectedResponse(format!(
            "Expected Array of size {}. Got: {:?}",
            size, other
        ))),
    }
}

/// Run the `set` test case
pub async fn run_set(
    mut conn: Box<dyn Connection>,
    opts: Options,
    requests_to_send: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut requests_sent = 0;
    let key_size = opts.get_key_size();
    let key_range = opts.key_range;
    let payload = bench_utils::generate_payload(opts.data_size);
    let client = ValkeyClient::default();
    while requests_sent < requests_to_send {
        let mut buffer = bytes::BytesMut::with_capacity(1024);
        for _ in 0..opts.pipeline {
            let key = bench_utils::generate_key(key_size, key_range);
            client.build_set_command(&mut buffer, &key, &payload);
        }

        let sw = StopWatch::default();
        let results = conn.send_recv_multi(&buffer, opts.pipeline).await?;
        // validate each response
        for obj in &results {
            expect_ok(obj)?;
        }

        stats::incr_requests(opts.pipeline);
        stats::record_latency(sw.elapsed_micros()?.try_into().unwrap_or(u64::MAX));
        requests_sent += opts.pipeline;
    }
    Ok(())
}

/// Run the `get` test case
pub async fn run_get(
    mut conn: Box<dyn Connection>,
    opts: Options,
    requests_to_send: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut requests_sent = 0;
    let key_size = opts.get_key_size();
    let key_range = opts.key_range;
    let client = ValkeyClient::default();
    while requests_sent < requests_to_send {
        let mut buffer = bytes::BytesMut::with_capacity(1024);
        for _ in 0..opts.pipeline {
            let key = bench_utils::generate_key(key_size, key_range);
            client.build_get_command(&mut buffer, &key);
        }

        let sw = StopWatch::default();
        let objects = conn.send_recv_multi(&buffer, opts.pipeline).await?;

        // validate each response
        for object in &objects {
            if expect_string_or_null(object)? {
                stats::incr_hits();
            }
        }

        stats::incr_requests(opts.pipeline);
        stats::record_latency(sw.elapsed_micros()?.try_into().unwrap_or(u64::MAX));
        requests_sent += opts.pipeline;
    }
    Ok(())
}

/// Run the `ping` test case
pub async fn run_ping(
    mut conn: Box<dyn Connection>,
    opts: Options,
) -> Result<(), Box<dyn std::error::Error>> {
    let requests_to_send = opts.client_requests();
    let mut requests_sent = 0;
    let client = ValkeyClient::default();
    while requests_sent < requests_to_send {
        let mut buffer = bytes::BytesMut::with_capacity(1024);
        for _ in 0..opts.pipeline {
            client.build_ping_command(&mut buffer);
        }

        let sw = StopWatch::default();
        let objects = conn.send_recv_multi(&buffer, opts.pipeline).await?;
        // validate each response
        for object in &objects {
            expect_pong(object)?;
        }

        stats::incr_requests(opts.pipeline);
        stats::record_latency(sw.elapsed_micros()?.try_into().unwrap_or(u64::MAX));
        requests_sent += opts.pipeline;
    }
    Ok(())
}

/// Run the `incr` test case
pub async fn run_incr(
    mut conn: Box<dyn Connection>,
    opts: Options,
) -> Result<(), Box<dyn std::error::Error>> {
    let requests_to_send = opts.client_requests();
    let mut requests_sent = 0;
    let key_size = opts.get_key_size();
    let key_range = opts.key_range;
    let client = ValkeyClient::default();
    while requests_sent < requests_to_send {
        let mut buffer = bytes::BytesMut::with_capacity(1024);
        for _ in 0..opts.pipeline {
            let key = bench_utils::generate_key(key_size, key_range);
            client.build_incr_command(&mut buffer, &key, 1);
        }

        let sw = StopWatch::default();
        let objects = conn.send_recv_multi(&buffer, opts.pipeline).await?;

        // validate each response
        for object in &objects {
            expect_integer(object)?;
            stats::incr_hits();
        }

        stats::incr_requests(opts.pipeline);
        stats::record_latency(sw.elapsed_micros()?.try_into().unwrap_or(u64::MAX));
        requests_sent += opts.pipeline;
    }
    Ok(())
}

/// Run the `set` test case
pub async fn run_push(
    mut conn: Box<dyn Connection>,
    right: bool,
    opts: Options,
) -> Result<(), Box<dyn std::error::Error>> {
    let requests_to_send = opts.client_requests();
    let mut requests_sent = 0;
    let key_size = opts.get_key_size();
    let key_range = opts.key_range;
    let payload = bench_utils::generate_payload(opts.data_size);
    let client = ValkeyClient::default();
    while requests_sent < requests_to_send {
        let mut buffer = bytes::BytesMut::with_capacity(1024);
        for _ in 0..opts.pipeline {
            let key = bench_utils::generate_key(key_size, key_range);
            client.build_push_command(&mut buffer, &key, &payload, right);
        }

        let sw = StopWatch::default();
        let objects = conn.send_recv_multi(&buffer, opts.pipeline).await?;

        // validate each response
        for object in &objects {
            expect_integer(object)?;
        }
        stats::incr_requests(opts.pipeline);
        stats::record_latency(sw.elapsed_micros()?.try_into().unwrap_or(u64::MAX));
        requests_sent += opts.pipeline;
    }
    Ok(())
}

/// Run the `set` test case
pub async fn run_pop(
    mut conn: Box<dyn Connection>,
    right: bool,
    opts: Options,
) -> Result<(), Box<dyn std::error::Error>> {
    let requests_to_send = opts.client_requests();
    let mut requests_sent = 0;
    let key_size = opts.get_key_size();
    let key_range = opts.key_range;
    let client = ValkeyClient::default();
    while requests_sent < requests_to_send {
        let mut buffer = bytes::BytesMut::with_capacity(1024);
        for _ in 0..opts.pipeline {
            let key = bench_utils::generate_key(key_size, key_range);
            client.build_pop_command(&mut buffer, &key, right);
        }

        let sw = StopWatch::default();
        let objects = conn.send_recv_multi(&buffer, opts.pipeline).await?;

        // validate each response
        for object in &objects {
            if expect_string_or_null(object)? {
                stats::incr_hits();
            }
        }

        stats::incr_requests(opts.pipeline);
        stats::record_latency(sw.elapsed_micros()?.try_into().unwrap_or(u64::MAX));
        requests_sent += opts.pipeline;
    }
    Ok(())
}

/// Run the `hset` test case
pub async fn run_hset(
    mut conn: Box<dyn Connection>,
    opts: Options,
) -> Result<(), Box<dyn std::error::Error>> {
    let requests_to_send = opts.client_requests();
    let mut requests_sent = 0;
    let key_size = opts.get_key_size();
    let key_range = opts.key_range;
    let client = ValkeyClient::default();
    let payload = bench_utils::generate_payload(opts.data_size);
    let mut seq = 0usize;
    while requests_sent < requests_to_send {
        let mut buffer = bytes::BytesMut::with_capacity(1024);
        for _ in 0..opts.pipeline {
            seq += 1;
            let key = bench_utils::generate_key(key_size, key_range);
            let field = bytes::BytesMut::from(format!("field_{}", seq).as_str());
            client.build_hset_command(&mut buffer, &key, &field, &payload);
        }

        let sw = StopWatch::default();
        let objects = conn.send_recv_multi(&buffer, opts.pipeline).await?;

        // validate each response
        for object in &objects {
            if expect_integer_or_null(object)? {
                stats::incr_hits();
            }
        }

        stats::incr_requests(opts.pipeline);
        stats::record_latency(sw.elapsed_micros()?.try_into().unwrap_or(u64::MAX));
        requests_sent += opts.pipeline;
    }
    Ok(())
}

lazy_static::lazy_static! {
    static ref VEC_COUNTER: AtomicU64 = AtomicU64::default();
}

/// Initialise the vector generator seed to `count`
pub fn set_vec_index_generator_seed(seed: u64) {
    VEC_COUNTER.fetch_add(seed, Ordering::Relaxed);
}

/// Run the `hset` test case
pub async fn run_vecdb_ingest(
    mut conn: Box<dyn Connection>,
    opts: Options,
) -> Result<(), Box<dyn std::error::Error>> {
    let requests_to_send = opts.client_requests();
    let mut requests_sent = 0;
    let client = ValkeyClient::default();

    // Create the index
    let mut create_buffer = bytes::BytesMut::default();
    client.build_ft_create_command(&mut create_buffer, &opts);
    tracing::debug!(
        "Creating index: {}",
        String::from_utf8_lossy(&create_buffer).to_string()
    );
    let obj = conn.send_recv(&create_buffer).await?;
    expect_ok_or_error_contains(&obj, "already exists")?;

    let prefix = options::vecdb_index_prefix();
    while requests_sent < requests_to_send {
        let mut commands = Vec::<String>::with_capacity(opts.pipeline);
        for _ in 0..opts.pipeline {
            let next_val = VEC_COUNTER.fetch_add(1, Ordering::Relaxed);
            let key = format!("{}:{}", prefix, next_val);
            let payload = bench_utils::generate_vector(opts.dim);
            commands.push(client.build_vecdb_hset_command(&key, "vector", &payload));
        }

        let buffer_string: String = commands.join(" ").into();
        let sw = StopWatch::default();
        tracing::debug!("Running command: {}", buffer_string);

        let buffer = BytesMut::from(buffer_string.as_bytes());
        let objects = conn.send_recv_multi(&buffer, opts.pipeline).await?;

        // validate each response
        for object in &objects {
            if expect_integer_or_null(object)? {
                stats::incr_hits();
            }
        }

        stats::incr_requests(opts.pipeline);
        stats::record_latency(sw.elapsed_micros()?.try_into().unwrap_or(u64::MAX));
        requests_sent += opts.pipeline;
    }
    Ok(())
}

/// Run the `hset` test case
pub async fn run_ftsearch(
    mut conn: Box<dyn Connection>,
    opts: Options,
) -> Result<(), Box<dyn std::error::Error>> {
    let requests_to_send = opts.client_requests();
    let mut requests_sent = 0;
    let client = ValkeyClient::default();

    let index_name = options::vecdb_index_name();
    while requests_sent < requests_to_send {
        let mut commands = Vec::<String>::with_capacity(opts.pipeline);
        for _ in 0..opts.pipeline {
            let search_me = bench_utils::generate_vector(opts.dim);
            commands.push(client.build_ftsearch_query(&index_name, opts.knn, &search_me));
        }

        let buffer_string: String = commands.join(" ").into();
        let sw = StopWatch::default();
        tracing::debug!("Running command: {}", buffer_string);

        let buffer = BytesMut::from(buffer_string.as_bytes());
        let objects = conn.send_recv_multi(&buffer, opts.pipeline).await?;

        // validate each response
        for object in &objects {
            // we expect an array of KNN entries
            if expect_array_of_size(object, opts.knn.saturating_mul(2).saturating_add(1))? {
                stats::incr_hits();
            }
        }

        stats::incr_requests(opts.pipeline);
        stats::record_latency(sw.elapsed_micros()?.try_into().unwrap_or(u64::MAX));
        requests_sent += opts.pipeline;
    }
    Ok(())
}
