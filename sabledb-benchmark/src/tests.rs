use crate::valkey_client::{StreamType, ValkeyClient};
use crate::{bench_utils, sb_options::Options, stats};
use sbcommonlib::{stopwatch::StopWatch, ValkeyObject};

/// Run the `set` test case
pub async fn run_set(
    mut stream: StreamType,
    opts: Options,
    requests_to_send: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut requests_sent = 0;
    let key_size = opts.get_key_size();
    let key_range = opts.key_range;
    let payload = bench_utils::generate_payload(opts.data_size);
    let mut client = ValkeyClient::default();
    let status_ok = ValkeyObject::Status("OK".into());
    while requests_sent < requests_to_send {
        let mut buffer = bytes::BytesMut::with_capacity(1024);
        for _ in 0..opts.pipeline {
            let key = bench_utils::generate_key(key_size, key_range);
            client.build_set_command(&mut buffer, &key, &payload);
        }

        let sw = StopWatch::default();
        client.write_buffer(&mut stream, &buffer).await?;
        // read "pipeline" responses
        for _ in 0..opts.pipeline {
            let response = client.read_response(&mut stream).await?;
            if !response.eq(&status_ok) {
                tracing::error!("Expected 'OK'");
            }
        }

        stats::incr_requests(opts.pipeline);
        stats::record_latency(sw.elapsed_micros()?.try_into().unwrap_or(u64::MAX));
        requests_sent += opts.pipeline;
    }
    Ok(())
}

/// Run the `get` test case
pub async fn run_get(
    mut stream: StreamType,
    opts: Options,
    requests_to_send: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut requests_sent = 0;
    let key_size = opts.get_key_size();
    let key_range = opts.key_range;
    let mut client = ValkeyClient::default();
    while requests_sent < requests_to_send {
        let mut buffer = bytes::BytesMut::with_capacity(1024);
        for _ in 0..opts.pipeline {
            let key = bench_utils::generate_key(key_size, key_range);
            client.build_get_command(&mut buffer, &key);
        }

        let sw = StopWatch::default();
        client.write_buffer(&mut stream, &buffer).await?;

        // read "pipeline" responses
        for _ in 0..opts.pipeline {
            match client.read_response(&mut stream).await? {
                ValkeyObject::NullString => {}
                ValkeyObject::Str(_value) => {
                    stats::incr_hits();
                }
                other => {
                    tracing::error!("expected string or null-string. Got: {:?}", other);
                }
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
    mut stream: StreamType,
    opts: Options,
) -> Result<(), Box<dyn std::error::Error>> {
    let requests_to_send = opts.client_requests();
    let mut requests_sent = 0;
    let mut client = ValkeyClient::default();
    let status_pong = ValkeyObject::Status("PONG".into());
    while requests_sent < requests_to_send {
        let mut buffer = bytes::BytesMut::with_capacity(1024);
        for _ in 0..opts.pipeline {
            client.build_ping_command(&mut buffer);
        }

        let sw = StopWatch::default();
        client.write_buffer(&mut stream, &buffer).await?;
        // read "pipeline" responses
        for _ in 0..opts.pipeline {
            let response = client.read_response(&mut stream).await?;
            if !response.eq(&status_pong) {
                tracing::error!("Expected 'PONG'");
            }
        }

        stats::incr_requests(opts.pipeline);
        stats::record_latency(sw.elapsed_micros()?.try_into().unwrap_or(u64::MAX));
        requests_sent += opts.pipeline;
    }
    Ok(())
}

/// Run the `incr` test case
pub async fn run_incr(
    mut stream: StreamType,
    opts: Options,
) -> Result<(), Box<dyn std::error::Error>> {
    let requests_to_send = opts.client_requests();
    let mut requests_sent = 0;
    let key_size = opts.get_key_size();
    let key_range = opts.key_range;
    let mut client = ValkeyClient::default();
    while requests_sent < requests_to_send {
        let mut buffer = bytes::BytesMut::with_capacity(1024);
        for _ in 0..opts.pipeline {
            let key = bench_utils::generate_key(key_size, key_range);
            client.build_incr_command(&mut buffer, &key, 1);
        }

        let sw = StopWatch::default();
        client.write_buffer(&mut stream, &buffer).await?;

        // read "pipeline" responses
        for _ in 0..opts.pipeline {
            match client.read_response(&mut stream).await? {
                ValkeyObject::Integer(_val) => {
                    stats::incr_hits();
                }
                other => {
                    tracing::error!("expected Integer. Got: {:?}", other);
                }
            }
        }

        stats::incr_requests(opts.pipeline);
        stats::record_latency(sw.elapsed_micros()?.try_into().unwrap_or(u64::MAX));
        requests_sent += opts.pipeline;
    }
    Ok(())
}

/// Run the `set` test case
pub async fn run_push(
    mut stream: StreamType,
    right: bool,
    opts: Options,
) -> Result<(), Box<dyn std::error::Error>> {
    let requests_to_send = opts.client_requests();
    let mut requests_sent = 0;
    let key_size = opts.get_key_size();
    let key_range = opts.key_range;
    let payload = bench_utils::generate_payload(opts.data_size);
    let mut client = ValkeyClient::default();
    while requests_sent < requests_to_send {
        let mut buffer = bytes::BytesMut::with_capacity(1024);
        for _ in 0..opts.pipeline {
            let key = bench_utils::generate_key(key_size, key_range);
            client.build_push_command(&mut buffer, &key, &payload, right);
        }

        let sw = StopWatch::default();
        client.write_buffer(&mut stream, &buffer).await?;
        // read "pipeline" responses
        for _ in 0..opts.pipeline {
            match client.read_response(&mut stream).await? {
                ValkeyObject::Integer(_list_length) => {}
                other => {
                    tracing::error!("expected Integer. Got: {:?}", other);
                }
            }
        }
        stats::incr_requests(opts.pipeline);
        stats::record_latency(sw.elapsed_micros()?.try_into().unwrap_or(u64::MAX));
        requests_sent += opts.pipeline;
    }
    Ok(())
}

/// Run the `set` test case
pub async fn run_pop(
    mut stream: StreamType,
    right: bool,
    opts: Options,
) -> Result<(), Box<dyn std::error::Error>> {
    let requests_to_send = opts.client_requests();
    let mut requests_sent = 0;
    let key_size = opts.get_key_size();
    let key_range = opts.key_range;
    let mut client = ValkeyClient::default();
    while requests_sent < requests_to_send {
        let mut buffer = bytes::BytesMut::with_capacity(1024);
        for _ in 0..opts.pipeline {
            let key = bench_utils::generate_key(key_size, key_range);
            client.build_pop_command(&mut buffer, &key, right);
        }

        let sw = StopWatch::default();
        client.write_buffer(&mut stream, &buffer).await?;

        // read "pipeline" responses
        for _ in 0..opts.pipeline {
            match client.read_response(&mut stream).await? {
                ValkeyObject::NullString => {}
                ValkeyObject::Str(_value) => {
                    stats::incr_hits();
                }
                other => {
                    tracing::error!("expected string or null-string. Got: {:?}", other);
                }
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
    mut stream: StreamType,
    opts: Options,
) -> Result<(), Box<dyn std::error::Error>> {
    let requests_to_send = opts.client_requests();
    let mut requests_sent = 0;
    let key_size = opts.get_key_size();
    let key_range = opts.key_range;
    let mut client = ValkeyClient::default();
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
        client.write_buffer(&mut stream, &buffer).await?;

        // read "pipeline" responses
        for _ in 0..opts.pipeline {
            match client.read_response(&mut stream).await? {
                ValkeyObject::NullString => {}
                ValkeyObject::Integer(_num) => {
                    stats::incr_hits();
                }
                other => {
                    tracing::error!("expected string or number. Got: {:?}", other);
                }
            }
        }

        stats::incr_requests(opts.pipeline);
        stats::record_latency(sw.elapsed_micros()?.try_into().unwrap_or(u64::MAX));
        requests_sent += opts.pipeline;
    }
    Ok(())
}
