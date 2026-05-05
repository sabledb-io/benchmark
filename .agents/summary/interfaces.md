# Interfaces and APIs

## Public Interfaces

### 1. Command-Line Interface (CLI)

**Entry Point:** `sb` binary

**Basic Usage:**
```bash
sb [OPTIONS]
```

**Core Options:**

| Option | Short | Type | Default | Description |
|--------|-------|------|---------|-------------|
| `--help` | - | flag | - | Print help message |
| `--connections` | `-c` | usize | 512 | Total number of connections |
| `--threads` | - | usize | 1 | Number of worker threads |
| `--host` | `-h` | String | 127.0.0.1 | Server host address |
| `--port` | `-p` | usize | 6379 | Server port |
| `--test` | `-t` | String | set | Test type to run |
| `--data-size` | `-d` | usize | 256 | Payload size in bytes |
| `--key-size` | `-k` | usize | auto | Key size in bytes |
| `--key-range` | `-r` | usize | 1000000 | Number of unique keys |
| `--num-requests` | `-n` | usize | 1000000 | Total requests to execute |
| `--pipeline` | `-P` | usize | 1 | Pipeline depth |
| `--randomize` | `-z` | flag | false | Use random key generation |
| `--tls` / `--ssl` | - | flag | false | Enable TLS encryption |
| `--log-level` | `-l` | String | error | Logging level |
| `--preset` | `-s` | String | - | Use preset from config file |
| `--cluster` | - | flag | false | Use cluster mode |
| `--json` | - | flag | false | Output results as JSON |

**Test Types:**
- `set` - SET command benchmark
- `get` - GET command benchmark
- `setget` - Mixed SET/GET workload
- `ping` - PING command benchmark
- `incr` - INCR command benchmark
- `lpush` / `rpush` - List push operations
- `lpop` / `rpop` - List pop operations
- `hset` - Hash set operations
- `vecdb_ingest` - Vector database ingestion

**Special Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--setget-ratio` | String | 1:4 | SET:GET ratio for setget test |
| `--dim` | usize | 128 | Vector dimension for vecdb_ingest |
| `--vecdb-index` | String | my_index,my_prefix | Index name and prefix |

**Usage Examples:**

```bash
# Basic SET benchmark
sb -t set -n 1000000 -c 50

# Mixed workload with 1 SET per 4 GETs
sb -t setget --setget-ratio 1:4 -n 1000000

# Random keys with TLS
sb -t get -z --tls -h myserver.com

# Using preset
sb --preset fill-database

# Cluster mode
sb --cluster -h 127.0.0.1 -p 7000 -t set

# JSON output for automation
sb -t set -n 10000 --json
```

---

### 2. Configuration File Interface

**File Location:** `$HOME/.sb.ini`

**Format:** INI file with named sections

**Structure:**
```ini
[preset-name]
option1 value1
option2 value2
...
```

**Example:**
```ini
[fill-database]
--threads 10
-c 512
--pipeline 5
-d 64
-n 5000000
-r 5000000
-t set

[read-heavy]
--threads 8
-c 512
-d 64
-n 10000000
-r 1000000
-t get
-z

[mixed-workload]
--threads 4
-c 256
-t setget
--setget-ratio 1:10
-n 5000000
```

**Usage:**
```bash
sb --preset fill-database
```

---

### 3. Connection Trait

**Purpose:** Abstract interface for single-node and cluster connections

**Definition:**
```rust
#[async_trait]
pub trait Connection {
    /// Send a single request and receive response
    async fn send_request(
        &mut self, 
        buffer: &[u8]
    ) -> Result<BytesMut, CommonError>;
    
    /// Send multiple requests (for vector DB ingestion)
    async fn send_vecdb_ingest_request(
        &mut self, 
        requests: Vec<BytesMut>
    ) -> Result<Vec<BytesMut>, CommonError>;
}
```

**Implementations:**
1. `ValkeyClient` - Single-node connection
2. `ValkeyCluster` - Cluster-aware connection

**Usage Pattern:**
```rust
async fn run_test(
    mut conn: impl Connection,
    opts: Options
) -> Result<(), Box<dyn std::error::Error>> {
    let buffer = build_request();
    let response = conn.send_request(&buffer).await?;
    // process response
    Ok(())
}
```

---

### 4. ValkeyClient API

**Constructor:**
```rust
impl ValkeyClient {
    pub async fn connect(
        host: String,
        port: u16,
        use_tls: bool
    ) -> Result<Self, CommonError>
}
```

**Connection Trait Implementation:**
```rust
#[async_trait]
impl Connection for ValkeyClient {
    async fn send_request(&mut self, buffer: &[u8]) 
        -> Result<BytesMut, CommonError>;
    
    async fn send_vecdb_ingest_request(&mut self, requests: Vec<BytesMut>) 
        -> Result<Vec<BytesMut>, CommonError>;
}
```

**Internal Methods:**
```rust
impl ValkeyClient {
    async fn read_response(&mut self) -> Result<ValkeyObject, CommonError>;
}
```

**Usage:**
```rust
let mut client = ValkeyClient::connect(
    "127.0.0.1".to_string(),
    6379,
    false
).await?;

let request = build_set_command("key1", "value1");
let response = client.send_request(&request).await?;
```

---

### 5. ValkeyCluster API

**Constructor:**
```rust
impl ValkeyCluster {
    pub async fn connect(
        host: String,
        port: u16,
        use_tls: bool
    ) -> Result<Self, CommonError>
}
```

**Public Functions:**
```rust
// Calculate hash slot for a key
pub fn calculate_slot(key: &[u8]) -> u16;
```

**Connection Trait Implementation:**
```rust
#[async_trait]
impl Connection for ValkeyCluster {
    async fn send_request(&mut self, buffer: &[u8]) 
        -> Result<BytesMut, CommonError>;
    
    async fn send_vecdb_ingest_request(&mut self, requests: Vec<BytesMut>) 
        -> Result<Vec<BytesMut>, CommonError>;
}
```

**Internal Methods:**
```rust
impl ValkeyCluster {
    async fn get_or_create_connection(
        &mut self,
        host: &str,
        port: u16
    ) -> Result<&mut ValkeyClient, CommonError>;
    
    async fn send_to_node(
        &mut self,
        buffer: &[u8]
    ) -> Result<(String, u16, BytesMut), CommonError>;
}
```

**Usage:**
```rust
let mut cluster = ValkeyCluster::connect(
    "127.0.0.1".to_string(),
    7000,
    false
).await?;

let request = build_set_command("key1", "value1");
let response = cluster.send_request(&request).await?;
// Automatically routes to correct node based on key hash
```

**Slot Calculation:**
```rust
let key = b"mykey";
let slot = calculate_slot(key);
// slot is in range 0-16383

// With hashtag
let key = b"user:{123}:name";
let slot = calculate_slot(key);
// Uses "123" for slot calculation
```

---

### 6. RespBuilderV2 API

**Purpose:** Build RESP protocol messages

**Constructor:**
```rust
let builder = RespBuilderV2::default();
```

**Methods:**

```rust
impl RespBuilderV2 {
    // Clear buffer and create complete messages
    pub fn bulk_string(&self, buffer: &mut BytesMut, content: &[u8]);
    pub fn ok(&self, buffer: &mut BytesMut);
    pub fn null_string(&self, buffer: &mut BytesMut);
    pub fn null_array(&self, buffer: &mut BytesMut);
    pub fn empty_string(&self, buffer: &mut BytesMut);
    pub fn empty_array(&self, buffer: &mut BytesMut);
    pub fn error_string(&self, buffer: &mut BytesMut, msg: &str);
    pub fn status_string(&self, buffer: &mut BytesMut, msg: &str);
    pub fn pong(&self, buffer: &mut BytesMut);
    
    // Append to existing buffer (for building arrays)
    pub fn add_array_len(&self, buffer: &mut BytesMut, len: usize);
    pub fn add_bulk_string(&self, buffer: &mut BytesMut, content: &[u8]);
    pub fn add_number_as_bulk_string<T: ToString>(
        &self,
        buffer: &mut BytesMut,
        number: T
    );
    pub fn add_null_string(&self, buffer: &mut BytesMut);
    pub fn add_null_array(&self, buffer: &mut BytesMut);
    pub fn add_array(&self, buffer: &mut BytesMut, items: &[&[u8]]);
}
```

**Usage Examples:**

```rust
let builder = RespBuilderV2::default();
let mut buffer = BytesMut::new();

// Build SET command: SET key value
builder.add_array_len(&mut buffer, 3);
builder.add_bulk_string(&mut buffer, b"SET");
builder.add_bulk_string(&mut buffer, b"mykey");
builder.add_bulk_string(&mut buffer, b"myvalue");
// Result: *3\r\n$3\r\nSET\r\n$5\r\nmykey\r\n$7\r\nmyvalue\r\n

// Build GET command: GET key
buffer.clear();
builder.add_array_len(&mut buffer, 2);
builder.add_bulk_string(&mut buffer, b"GET");
builder.add_bulk_string(&mut buffer, b"mykey");

// Build INCR command with numeric argument
buffer.clear();
builder.add_array_len(&mut buffer, 2);
builder.add_bulk_string(&mut buffer, b"INCRBY");
builder.add_number_as_bulk_string(&mut buffer, 42);
```

---

### 7. RespResponseParserV2 API

**Purpose:** Parse RESP protocol responses

**Main Method:**
```rust
impl RespResponseParserV2 {
    pub fn parse_response(buffer: &[u8]) 
        -> Result<ResponseParseResult, CommonError>;
}
```

**Return Types:**
```rust
pub enum ResponseParseResult {
    NeedMoreData,
    Ok((usize, ValkeyObject)),
}

pub enum ValkeyObject {
    Status(BytesMut),      // +OK\r\n
    Error(BytesMut),       // -ERR message\r\n
    Str(BytesMut),         // $5\r\nhello\r\n
    Array(Vec<ValkeyObject>), // *2\r\n...
    NullArray,             // *-1\r\n
    NullString,            // $-1\r\n
    Integer(u64),          // :42\r\n
}
```

**ValkeyObject Methods:**
```rust
impl ValkeyObject {
    pub fn integer(&self) -> Result<u64, CommonError>;
    pub fn status(&self) -> Result<BytesMut, CommonError>;
    pub fn string(&self) -> Result<BytesMut, CommonError>;
    pub fn error_string(&self) -> Result<BytesMut, CommonError>;
    pub fn array(&self) -> Result<Vec<ValkeyObject>, CommonError>;
    pub fn is_null_string(&self) -> bool;
}
```

**Usage Pattern:**
```rust
let mut buffer = BytesMut::from("+OK\r\n");
match RespResponseParserV2::parse_response(&buffer)? {
    ResponseParseResult::Ok((consumed, obj)) => {
        buffer.advance(consumed);
        match obj {
            ValkeyObject::Status(s) => println!("Status: {:?}", s),
            ValkeyObject::Error(e) => eprintln!("Error: {:?}", e),
            ValkeyObject::Str(s) => println!("String: {:?}", s),
            ValkeyObject::Integer(n) => println!("Number: {}", n),
            _ => {}
        }
    }
    ResponseParseResult::NeedMoreData => {
        // Read more bytes from socket
    }
}
```

---

### 8. Statistics API

**Purpose:** Collect and report performance metrics

**Public Functions:**

```rust
// Increment counters
pub fn incr_requests_processed(count: usize);
pub fn incr_hits(count: usize);
pub fn incr_setget_set_tasks(count: usize);
pub fn incr_setget_get_tasks(count: usize);

// Thread management
pub fn incr_threads_running();
pub fn decr_threads_running();

// Latency tracking
pub fn record_latency(micros: u64);

// Progress tracking
pub fn finalise_progress_setup(total: u64);
pub fn update_progress(count: u64);
pub fn finish_progress();

// Query state
pub fn requests_processed() -> usize;
pub fn total_hits() -> usize;

// Output configuration
pub fn set_use_json_output(b: bool);
pub fn is_json_output() -> bool;
```

**Stats Collection:**
```rust
impl Stats {
    pub fn collect(opts: &Options, test_duration_millis: f64) -> Self;
}
```

**Output Structures:**
```rust
#[derive(Serialize, Debug)]
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

#[derive(Serialize, Debug)]
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
```

**Usage:**
```rust
use stats;

// During test execution
let sw = StopWatch::default();
sw.start();
// ... execute operation
sw.stop();
stats::record_latency(sw.elapsed_micros());
stats::incr_requests_processed(1);
stats::update_progress(1);

// After test completion
let duration_ms = test_stopwatch.elapsed_millis();
let stats = Stats::collect(&opts, duration_ms);

if stats::is_json_output() {
    println!("{}", serde_json::to_string_pretty(&stats)?);
} else {
    // Format and print human-readable output
}
```

---

### 9. Benchmark Utilities API

**Purpose:** Generate test data

**Functions:**

```rust
// Generate random payload of specified length
pub fn generate_payload(len: usize) -> BytesMut;

// Generate key (sequential or random based on mode)
pub fn generate_key(len: usize, key_range: usize) -> BytesMut;

// Configure key generation mode
pub fn set_randomize_keys(random: bool);

// Generate random vector for vector DB tests
pub fn generate_vector(dim: usize) -> String;
```

**Usage:**
```rust
use bench_utils;

// Set mode
bench_utils::set_randomize_keys(true);

// Generate data
let key = bench_utils::generate_key(10, 1000000);
let value = bench_utils::generate_payload(256);

// For vector DB
let vector_hex = bench_utils::generate_vector(128);
```

---

### 10. Test Runner Interface

**Pattern:** All test runners follow the same signature

**Signature:**
```rust
pub async fn run_TESTNAME(
    conn: impl Connection,
    opts: Options,
    requests_count: usize
) -> Result<(), Box<dyn std::error::Error>>
```

**Available Tests:**

```rust
pub async fn run_set(
    conn: impl Connection,
    opts: Options,
    requests_count: usize
) -> Result<(), Box<dyn std::error::Error>>;

pub async fn run_get(
    conn: impl Connection,
    opts: Options,
    requests_count: usize
) -> Result<(), Box<dyn std::error::Error>>;

pub async fn run_ping(
    conn: impl Connection,
    opts: Options
) -> Result<(), Box<dyn std::error::Error>>;

pub async fn run_incr(
    conn: impl Connection,
    opts: Options
) -> Result<(), Box<dyn std::error::Error>>;

pub async fn run_push(
    conn: impl Connection,
    is_right: bool,
    opts: Options
) -> Result<(), Box<dyn std::error::Error>>;

pub async fn run_pop(
    conn: impl Connection,
    is_right: bool,
    opts: Options
) -> Result<(), Box<dyn std::error::Error>>;

pub async fn run_hset(
    conn: impl Connection,
    opts: Options
) -> Result<(), Box<dyn std::error::Error>>;

pub async fn run_vecdb_ingest(
    conn: impl Connection,
    opts: Options
) -> Result<(), Box<dyn std::error::Error>>;
```

---

### 11. Error Handling Interface

**Error Types:**

```rust
#[derive(Error, Debug, PartialEq, Eq)]
pub enum ParserError {
    #[error("Need more to data to complete operation")]
    NeedMoreData,
    #[error("Protocol error. `{0}`")]
    ProtocolError(String),
    #[error("Input too big")]
    BufferTooBig,
    #[error("Overflow occurred")]
    Overflow,
    #[error("Invalid input. {0}")]
    InvalidInput(String),
}

#[derive(Error, Debug)]
pub enum CommonError {
    #[error("Invalid argument error. {0}")]
    InvalidArgument(String),
    #[error("Error. {0}")]
    OtherError(String),
    #[error("Parse error. {0}")]
    Parser(#[from] ParserError),
    #[error("I/O error. {0}")]
    StdIoError(#[from] std::io::Error),
}
```

**Usage:**
```rust
fn my_function() -> Result<(), CommonError> {
    // Automatic conversion from io::Error
    let file = std::fs::File::open("test.txt")?;
    
    // Automatic conversion from ParserError
    let result = parse_something()?;
    
    // Manual error creation
    if invalid_condition {
        return Err(CommonError::InvalidArgument(
            "Invalid parameter".to_string()
        ));
    }
    
    Ok(())
}
```

---

## Integration Points

### Network Protocol Integration

**RESP Protocol Wire Format:**

```
Simple String:    +OK\r\n
Error:            -ERR message\r\n
Integer:          :1000\r\n
Bulk String:      $6\r\nfoobar\r\n
Null String:      $-1\r\n
Array:            *2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n
Null Array:       *-1\r\n
```

### TLS Integration

**Certificate Verification:**
- Custom `NoVerifier` struct bypasses certificate validation
- Suitable for benchmarking, not production use

**TLS Handshake:**
```rust
use tokio_rustls::{TlsConnector, rustls::ClientConfig};

let config = ClientConfig::builder()
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(NoVerifier))
    .with_no_client_auth();

let connector = TlsConnector::from(Arc::new(config));
let domain = ServerName::try_from(host.as_str())?;
let tls_stream = connector.connect(domain, tcp_stream).await?;
```

### Cluster Protocol Integration

**MOVED Redirection:**
```
Client -> Node1: GET key
Node1 -> Client: -MOVED 1234 127.0.0.1:7002\r\n
Client -> Node2: GET key
Node2 -> Client: $5\r\nvalue\r\n
```

**CLUSTER NODES:**
```
Client -> Any Node: CLUSTER NODES
Node -> Client: <node_id> <ip>:<port>@<cport> <flags> ...
```

---

## External Dependencies Interface

Key external crates and their usage:

| Crate | Purpose | Key Types Used |
|-------|---------|----------------|
| `tokio` | Async runtime | Runtime, TcpStream, spawn |
| `bytes` | Buffer management | BytesMut |
| `clap` | CLI parsing | Parser, derive macros |
| `tokio-rustls` | TLS support | TlsConnector, TlsStream |
| `hdrhistogram` | Latency tracking | Histogram<u64> |
| `indicatif` | Progress bars | ProgressBar |
| `serde` / `serde_json` | Serialization | Serialize, to_string_pretty |
| `thiserror` | Error handling | Error derive macro |
| `rand` | Random generation | random(), Rng |

---

## Output Interface

### Human-Readable Output

```
Using command line: sb -t set -n 1000000 -c 512
Using cluster client: false

[Progress bar showing completion]

=== Test Results ===
Test Duration: 15 seconds
Connections: 512
Threads: 8
Total Requests: 1000000
RPS: 66666

Latency (milliseconds):
  Min: 0.123
  P50: 1.234
  P90: 2.345
  P95: 3.456
  P99: 5.678
  P99.5: 6.789
  P99.9: 8.901
  Max: 12.345
```

### JSON Output

```json
{
  "test_duration_secs": 15,
  "total_connections": 512,
  "total_threads": 8,
  "total_requests": 1000000,
  "total_hits": 0,
  "key_size": 7,
  "value_size": 256,
  "rps": 66666,
  "pipeline": 1,
  "latency_ms": {
    "pmin": 0.123,
    "p50": 1.234,
    "p90": 2.345,
    "p95": 3.456,
    "p99": 5.678,
    "p995": 6.789,
    "p999": 8.901,
    "pmax": 12.345
  },
  "options": { ... }
}
```
