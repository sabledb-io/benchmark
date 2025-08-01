use clap::Parser;
use colored::Colorize;
use ini::Ini;
use std::collections::HashMap;
use std::sync::RwLock;

lazy_static::lazy_static! {
    static ref PRESETS: RwLock<HashMap<String, String>> = RwLock::<HashMap<String, String>>::default();
    static ref VECDB_INDEX_NAME: RwLock<String> = RwLock::<String>::new("my_index".into());
    static ref VECDB_INDEX_PREFIX: RwLock<String> = RwLock::<String>::new("my_prefix".into());
}

pub fn vecdb_index_name() -> String {
    VECDB_INDEX_NAME.read().expect("mutex error").clone()
}

pub fn vecdb_index_prefix() -> String {
    VECDB_INDEX_PREFIX.read().expect("mutex error").clone()
}

use serde::Serialize;
#[derive(Parser, Debug, Clone, Serialize, Default)]
#[clap(disable_help_flag = true)]
pub struct Options {
    /// Print this help message and exit
    #[arg(long, action = clap::ArgAction::HelpLong)]
    help: Option<bool>,

    /// Total number of connections
    #[arg(short, long, default_value = "512")]
    pub connections: usize,

    /// Number of threads to use.
    /// Each thread will run "connections / threads" connections
    #[arg(long, default_value = "1")]
    pub threads: usize,

    /// Host address
    #[arg(short, long, default_value = "127.0.0.1")]
    pub host: String,

    /// Host port
    #[arg(short, long, default_value = "6379")]
    pub port: usize,

    /// test suits to run. Possible values are:
    /// "set", "get", "lpush", "lpop", "incr", "rpop", "rpush", "ping", "hset", "setget", "vecdb_ingest".
    /// Note that when the test is "setget", you can control the ratio by passing: "--setget-ratio"
    #[arg(short, long, default_value = "set", verbatim_doc_comment)]
    pub test: String,

    /// Payload data size
    #[arg(short, long, default_value = "256")]
    pub data_size: usize,

    /// Key size, in bytes. If not provided, the key size is calculated based on the requested key range.
    /// For example, if no "key_size" is provided and the "key_range" is 100,000, the key size will be 6
    #[arg(short, long, verbatim_doc_comment)]
    pub key_size: Option<usize>,

    /// When running vector DB ingestion ("-t vecdb_ingest") test, pass here the vector dimension size.
    #[arg(long, default_value = "128", verbatim_doc_comment)]
    pub dim: usize,

    /// When testing "vecdb_ingest", use this to pass the index name + the prefix as a comma separated strings
    #[arg(long, default_value = "my_index,my_prefix", verbatim_doc_comment)]
    pub vecdb_index: String,

    /// Number of unique keys in the benchmark
    #[arg(short = 'r', long, default_value = "1000000")]
    pub key_range: usize,

    /// Total number of requests
    #[arg(short, long, default_value = "1000000")]
    pub num_requests: usize,

    /// Log level
    #[arg(short, long, default_value = "error")]
    pub log_level: String,

    /// Use TLS handshake with SableDB / Valkey
    #[arg(long, default_value = "false")]
    pub tls: bool,

    /// Same as "--tls"
    #[arg(long, default_value = "false")]
    pub ssl: bool,

    /// Pipeline
    #[arg(short = 'P', long, default_value = "1")]
    pub pipeline: usize,

    /// The ratio between SET:GET when test is "SETGET".
    /// For example, passing "1:4" means: execute 1 SET for every 4 GET calls
    #[arg(long, default_value = "1:4", verbatim_doc_comment)]
    pub setget_ratio: Option<String>,

    /// Keys are generated using sequential manner, i.e. from "0" until "key-range" in an incremental step of "1".
    /// Passing "-z" or "--randomize" will generate random keys by generating random number from "0" -> "key-range".
    #[arg(short = 'z', long, default_value = "false", verbatim_doc_comment)]
    pub randomize: bool,

    /// Use preset command line. If set, "sb" will search for the preset name
    /// in the configuration file "$HOME/.sb.ini" with that exact name and use the command line
    /// set there.
    #[arg(short = 's', long, verbatim_doc_comment)]
    pub preset: Option<String>,

    /// Use cluster enabled client.
    #[arg(long, verbatim_doc_comment, default_value = "false")]
    pub cluster: bool,

    /// If set, the benchmark will dump a JSON report to stdout.
    #[arg(long, verbatim_doc_comment, default_value = "false")]
    pub json: bool,
}

impl Options {
    /// Finalise the values provided by the user
    pub fn finalise(&mut self) {
        if self.threads == 0 {
            self.threads = 1;
        }

        if self.connections == 0 {
            self.connections = 1;
        }

        if self.num_requests == 0 {
            self.num_requests = 1000;
        }

        // parse the vecdb_index
        let parts: Vec<&str> = self.vecdb_index.split(",").collect();
        let mut iter = parts.iter();
        let (Some(index_name), Some(index_prefix)) = (iter.next(), iter.next()) else {
            eprintln!(
                "{}: {}: expected comma separated format of: '<index-name>,<index-prefix>'",
                "error".red().bold(),
                "--vecdb-index".bold(),
            );
            std::process::exit(1);
        };

        if self.cluster && self.pipeline > 1 {
            eprintln!(
                "{}: cluster mode requested, changing pipeline value to 1",
                "NOTICE".yellow().bold(),
            );
            self.pipeline = 1;
        }

        *VECDB_INDEX_NAME.write().expect("mutex error") = index_name.to_string();
        *VECDB_INDEX_PREFIX.write().expect("mutex error") = index_prefix.to_string();
    }

    /// Return the number of connections ("tasks") per thread to start
    pub fn tasks_per_thread(&self) -> usize {
        self.connections.saturating_div(self.threads)
    }

    /// Number of requests per client
    pub fn client_requests(&self) -> usize {
        self.num_requests.saturating_div(self.connections)
    }

    /// Return true if should be using TLS connection
    pub fn tls_enabled(&self) -> bool {
        self.ssl || self.tls
    }

    /// Return true if output is JSON file
    pub fn is_json_output(&self) -> bool {
        self.json
    }

    /// If the test requested is "setget" return the ratio between
    /// the two: SET_COUNT:GET_COUNT, e.g. (1,4) -> perform 1 set for every 4 get calls
    pub fn get_setget_ratio(&self) -> Option<(f32, f32)> {
        if !self.test.eq("setget") {
            return None;
        }

        if let Some(ratio) = &self.setget_ratio {
            let parts: Vec<&str> = ratio.split(':').collect();
            let (Some(setcalls), Some(getcalls)) = (parts.first(), parts.get(1)) else {
                return Some((1.0, 4.0));
            };

            let setcalls = setcalls.parse::<f32>().unwrap_or(1.0);
            let getcalls = getcalls.parse::<f32>().unwrap_or(4.0);
            Some((setcalls, getcalls))
        } else {
            Some((1.0, 4.0))
        }
    }

    /// Return the key size. If `key_size` is provided return its value
    /// otherwise, calculate it from the size required to hold the maximum key value
    pub fn get_key_size(&self) -> usize {
        if let Some(len) = self.key_size {
            len
        } else {
            self.key_range
                .ilog10()
                .saturating_add(1)
                .try_into()
                .unwrap_or(usize::MAX)
        }
    }

    pub fn get_log_level(&self) -> tracing::Level {
        let log_level = self.log_level.to_lowercase();
        match log_level.as_str() {
            "trace" => tracing::Level::TRACE,
            "debug" => tracing::Level::DEBUG,
            "info" => tracing::Level::INFO,
            "warn" => tracing::Level::WARN,
            "error" => tracing::Level::ERROR,
            _ => tracing::Level::INFO,
        }
    }

    /// Initialise the options from the command line arguments + configuration file (if one exists)
    pub fn initialise() -> (Self, String) {
        let mut args: Vec<String> = std::env::args().collect();

        // Check if "--preset" was passed
        let mut preset_value = None;
        let mut has_preset = false;
        let mut iter = args.iter();
        while let Some(argument) = iter.next() {
            if argument.eq("--preset") {
                if let Some(value) = iter.next() {
                    preset_value = Some(value.clone());
                    has_preset = true;
                    break;
                }
            }
        }

        let preset_value = match (has_preset, preset_value) {
            (true, None) => {
                eprintln!("{}: --preset is missing a value", "error".red().bold());
                std::process::exit(1);
            }
            (false, _) => {
                // No preset is requested
                let cmdline = args.join(" ");
                return (Self::parse_from(args), cmdline);
            }
            (true, Some(preset_value)) => preset_value,
        };

        #[cfg(windows)]
        let home = "USERPROFILE";
        #[cfg(not(windows))]
        let home = "HOME";
        let Ok(homedir) = std::env::var(home) else {
            eprintln!(
                "{}: could not locate environment variable {}",
                "error".red().bold(),
                home
            );
            std::process::exit(1);
        };

        let mut filepath = std::path::PathBuf::from(homedir);
        filepath.push(".sb.ini");
        let Ok(content) = std::fs::read_to_string(&filepath) else {
            eprintln!(
                "{}: could not read configuration file '{}'",
                "error".red().bold(),
                filepath.display()
            );
            std::process::exit(1);
        };

        let Ok(config) = Ini::load_from_str(content.as_str()) else {
            eprintln!(
                "{}: failed to parse INI file '{}'",
                "error".red().bold(),
                filepath.display()
            );
            std::process::exit(1);
        };

        // Read the sections, each section is the name of the preset
        for (name, props) in &config {
            let Some(name) = name else {
                continue;
            };
            if let Some(command) = props.get("command") {
                PRESETS
                    .write()
                    .expect("preset lock error")
                    .insert(name.to_string(), command.to_string());
            }
        }

        // read the value
        let presets = PRESETS.read().expect("preset lock error");
        let Some(content) = presets.get(&preset_value) else {
            eprintln!(
                "{}: preset name '{}' could not be found in configuration file: '{}'",
                "error".red().bold(),
                preset_value.bold(),
                filepath.display()
            );
            std::process::exit(1);
        };

        // We found the preset

        // Make sure no extra chars exists in the content
        let content = content.trim();

        // Create the command line args: exe <file args> <cmd line args>
        let mut preset_args: Vec<String> = content.split(' ').map(|s| s.to_string()).collect();
        let exe = args.remove(0);
        preset_args.extend(args);
        preset_args.insert(0, exe);

        let cmdline = preset_args.join(" ");
        let options: Options = Self::parse_from(preset_args);
        (options, cmdline)
    }
}
