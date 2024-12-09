use clap::Parser;

#[derive(Parser, Debug, Clone)]
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
    /// "set", "get", "lpush", "lpop", "incr", "rpop", "rpush", "ping", "hset", "setget".
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

    /// Number of unique keys in the benchmark
    #[arg(short = 'r', long, default_value = "1000000")]
    pub key_range: usize,

    /// Total number of requests
    #[arg(short, long, default_value = "1000000")]
    pub num_requests: usize,

    /// Log level
    #[arg(short, long)]
    pub log_level: Option<tracing::Level>,

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

    /// Initialise the options from the command line arguments + configuration file (if one exists)
    pub fn initialise() -> (Self, String) {
        let mut args: Vec<String> = std::env::args().collect();

        #[cfg(windows)]
        let home = "USERPROFILE";
        #[cfg(not(windows))]
        let home = "HOME";
        let Ok(homedir) = std::env::var(home) else {
            let cmdline = args.join(" ");
            return (Self::parse_from(args), cmdline);
        };

        let mut filepath = std::path::PathBuf::from(homedir);
        filepath.push(".sabledb-benchmark");
        let Ok(content) = std::fs::read_to_string(&filepath) else {
            let cmdline = args.join(" ");
            return (Self::parse_from(args), cmdline);
        };

        // Make sure no extra chars exists in the content
        let content = content.trim();

        // Create the command line args: exe <file args> <cmd line args>
        let mut config_args: Vec<String> = content.split(' ').map(|s| s.to_string()).collect();
        let exe = args.remove(0);
        config_args.extend(args);
        config_args.insert(0, exe);

        let cmdline = config_args.join(" ");
        (Self::parse_from(config_args), cmdline)
    }
}
