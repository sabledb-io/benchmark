mod bench_utils;
mod sb_options;
mod stats;
mod tests;
mod valkey_client;

use colored::Colorize;
use num_format::{Locale, ToFormattedString};
use sb_options::Options;
use stats::Stats;
use valkey_client::{ValkeyClient, ValkeyCluster};

/// Thread main function
async fn thread_main(opts: Options) -> Result<(), Box<dyn std::error::Error>> {
    let task_count = opts.tasks_per_thread();
    let local = tokio::task::LocalSet::new();

    match opts.get_setget_ratio() {
        Some((setcalls, getcalls)) if (setcalls >= 1.0 && getcalls >= 1.0) => {
            // Special test case: "setget"
            let task_count = task_count as f32;
            let set_multiplier = setcalls / (getcalls + setcalls); // 1:4 -> 1 / 5 => 0.2, 3:3 => 3 / 6 => 0.5
            let get_multiplier = 1.0 - set_multiplier;
            let set_tasks_count = (task_count * set_multiplier).floor() as usize;
            let get_tasks_count = (task_count * get_multiplier).ceil() as usize;

            stats::incr_setget_get_tasks(get_tasks_count);
            stats::incr_setget_set_tasks(set_tasks_count);

            // Launch "SET" task counts
            for _ in 0..set_tasks_count {
                // span task per connection
                let mut opts_clone = opts.clone();
                opts_clone.test = String::from("set");
                local.spawn_local(async move {
                    let requests_count = opts_clone.client_requests();
                    if let Err(e) = task_main(opts_clone, requests_count).await {
                        tracing::error!("{:?} client error. {:?}", std::thread::current().id(), e);
                    }
                });
            }
            // Launch "GET" task counts
            for _ in 0..get_tasks_count {
                // span task per connection
                let mut opts_clone = opts.clone();
                opts_clone.test = String::from("get");
                local.spawn_local(async move {
                    let requests_count = opts_clone.client_requests();
                    if let Err(e) = task_main(opts_clone, requests_count).await {
                        tracing::error!("{:?} client error. {:?}", std::thread::current().id(), e);
                    }
                });
            }
        }
        _ => {
            for _ in 0..task_count {
                // span task per connection
                let opts_clone = opts.clone();
                local.spawn_local(async move {
                    let requests_count = opts_clone.client_requests();
                    if let Err(e) = task_main(opts_clone, requests_count).await {
                        tracing::error!("{:?} client error. {:?}", std::thread::current().id(), e);
                    }
                });
            }
        }
    }

    // wait for the tasks to complete
    local.await;

    // remove this thread from the pool
    stats::decr_threads_running();
    Ok(())
}

/// Client main function
async fn task_main(
    mut opts: Options,
    requests_count: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    const LIST_KEY_RANGE: usize = 1000;
    let conn = if opts.cluster {
        ValkeyCluster::connect(opts.host.clone(), opts.port as u16, opts.tls_enabled()).await?
    } else {
        ValkeyClient::connect(opts.host.clone(), opts.port as u16, opts.tls_enabled()).await?
    };

    match opts.test.as_str() {
        "set" => tests::run_set(conn, opts, requests_count).await?,
        "get" => tests::run_get(conn, opts, requests_count).await?,
        "ping" => tests::run_ping(conn, opts).await?,
        "incr" => tests::run_incr(conn, opts).await?,
        "rpush" => {
            opts.key_range = LIST_KEY_RANGE;
            tests::run_push(conn, true, opts).await?;
        }
        "rpop" => {
            opts.key_range = LIST_KEY_RANGE;
            tests::run_pop(conn, true, opts).await?;
        }
        "lpush" => {
            opts.key_range = LIST_KEY_RANGE;
            tests::run_push(conn, false, opts).await?;
        }
        "lpop" => {
            opts.key_range = LIST_KEY_RANGE;
            tests::run_pop(conn, false, opts).await?;
        }
        "hset" => {
            opts.key_range = LIST_KEY_RANGE;
            tests::run_hset(conn, opts).await?;
        }
        "vecdb_ingest" => tests::run_vecdb_ingest(conn, opts).await?,
        _ => {
            panic!("don't know how to run test: `{}`", opts.test);
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (mut args, cmdline) = Options::initialise();
    args.finalise();

    stats::set_use_json_output(args.is_json_output());

    if args.randomize {
        bench_utils::set_randomize_keys(true);
    }

    // prepare log formatter
    let debug_level = args.get_log_level();
    tracing_subscriber::fmt::fmt()
        .with_thread_names(true)
        .with_thread_ids(true)
        .with_max_level(debug_level)
        .init();

    if !stats::is_json_output() {
        println!("{}: {}", "Using command line:".bold(), cmdline.italic());
        if args.cluster {
            println!(
                "{}: {}",
                "Using cluster client".bold(),
                "true".bold().green().italic()
            );
        } else {
            println!(
                "{}: {}",
                "Using cluster client".bold(),
                "false".bold().italic()
            );
        }
    }

    // panic! should go to the log
    std::panic::set_hook(Box::new(|e| {
        let errmsg = format!("{}", e);
        let lines = errmsg.split('\n');
        for line in lines.into_iter() {
            tracing::error!("{}", line);
        }
    }));

    let mut handles = Vec::new();
    tracing::debug!("Total requests: {}", args.num_requests);
    tracing::debug!("Test: {}", args.test.to_uppercase());
    tracing::debug!("Threads: {}", args.threads);
    tracing::debug!("Requests per connection: {}", args.client_requests());
    tracing::debug!("Connections: {}", args.connections);
    tracing::debug!("Conn per thread: {}", args.tasks_per_thread());
    tracing::debug!("Key space: {}", args.key_range);
    tracing::debug!("Key size: {}", args.get_key_size());
    tracing::debug!("Data size: {}", args.data_size);

    stats::finalise_progress_setup(args.num_requests as u64);

    // Launch the threads. In turn, each thread will launch a N clients each running
    // within a dedicated tokio's task
    for _ in 0..args.threads {
        let args_clone = args.clone();
        handles.push(
            std::thread::Builder::new()
                .name("Worker".to_string())
                .spawn(move || {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .thread_name("Worker")
                        .build()
                        .unwrap_or_else(|e| {
                            panic!("failed to create tokio runtime. {:?}", e);
                        });

                    rt.block_on(async move {
                        thread_main(args_clone).await.unwrap();
                    });
                })?,
        );
        stats::incr_threads_running();
    }

    // wait for all threads to join
    let sw = sbcommonlib::stopwatch::StopWatch::default();
    for h in handles {
        let _ = h.join();
    }

    stats::finish_progress();
    let test_duration_ms = (sw.elapsed_micros()? / 1000) as f64; // duration in MS

    if !stats::is_json_output() {
        // calculate the RPS
        let count = stats::requests_processed() as f64;
        let hits = stats::total_hits() as f64;

        let mut requests_per_ms = count / test_duration_ms;
        requests_per_ms *= 1000.0;
        let requests_per_ms: usize = requests_per_ms as usize;
        println!(
            "\n    RPS: {}",
            requests_per_ms
                .to_formatted_string(&Locale::en)
                .bold()
                .green(),
        );
        println!(
            "    Hit rate: {}",
            format!("{}%", hits / count * 100.0).bold().green()
        );
        if args.get_setget_ratio().is_some() {
            println!("    GET clients count: {}", stats::setget_get_tasks());
            println!("    SET clients count: {}", stats::setget_set_tasks());
        }

        println!("    Key size  : {} Bytes", args.get_key_size());
        println!("    Value size: {} Bytes", args.data_size);
        stats::print_latency();
    } else {
        let stats = Stats::collect(&args, test_duration_ms);
        println!(
            "{}",
            serde_json::to_string_pretty(&stats).expect("failed to serialise stats to JSON")
        );
    }
    Ok(())
}
