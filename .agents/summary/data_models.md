# Data Models and Structures

## Core Data Structures

### 1. Options (Configuration)

**Location:** `sabledb-benchmark/src/sb_options.rs`

**Purpose:** Hold all command-line configuration and derived settings

```rust
#[derive(Parser, Debug, Clone, Serialize, Default)]
pub struct Options {
    // Connection settings
    pub connections: usize,        // Total connections
    pub threads: usize,            // Worker threads
    pub host: String,              // Server host
    pub port: usize,               // Server port
    pub tls: bool,                 // TLS enabled
    pub ssl: bool,                 // SSL enabled (alias for tls)
    pub cluster: bool,             // Cluster mode
    
    // Test configuration
    pub test: String,              // Test type (set, get, ping, etc.)
    pub num_requests: usize,       // Total requests to execute
    pub pipeline: usize,           // Pipeline depth
    
    // Data generation
    pub data_size: usize,          // Payload size in bytes
    pub key_size: Option<usize>,   // Key size (auto-calculated if None)
    pub key_range: usize,          // Number of unique keys
    pub randomize: bool,           // Random vs sequential keys
    
    // Special test options
    pub setget_ratio: Option<String>, // SET:GET ratio for setget test
    pub dim: usize,                // Vector dimension for vecdb_ingest
    pub vecdb_index: String,       // Index name and prefix
    
    // Output and logging
    pub log_level: String,         // Log level (error, warn, info, debug, trace)
    pub json: bool,                // JSON output format
    pub preset: Option<String>,    // Preset name from config file
}
```

**Derived/Calculated Methods:**
```rust
impl Options {
    // Calculate requests per connection
    pub fn client_requests(&self) -> usize {
        (self.num_requests / self.connections).max(1)
    }
    
    // Calculate connections per thread
    pub fn tasks_per_thread(&self) -> usize {
        (self.connections / self.threads).max(1)
    }
    
    // Get or calculate key size
    pub fn get_key_size(&self) -> usize {
        self.key_size.unwrap_or_else(|| {
            self.key_range.to_string().len()
        })
    }
    
    // Parse setget ratio
    pub fn get_setget_ratio(&self) -> Option<(f32, f32)> {
        // Parses "1:4" into (1.0, 4.0)
    }
    
    // Check if TLS is enabled
    pub fn tls_enabled(&self) -> bool {
        self.tls || self.ssl
    }
}
```

---

### 2. ValkeyObject (RESP Data Type)

**Location:** `common/src/resp_response_parser_v2.rs`

**Purpose:** Represent parsed RESP protocol responses

```rust
#[derive(PartialEq, Eq, Debug, Clone)]
pub enum ValkeyObject {
    // Simple string: +OK\r\n
    Status(BytesMut),
    
    // Error: -ERR message\r\n
    Error(BytesMut),
    
    // Bulk string: $5\r\nhello\r\n
    Str(BytesMut),
    
    // Array: *2\r\n...
    Array(Vec<ValkeyObject>),
    
    // Null array: *-1\r\n
    NullArray,
    
    // Null string: $-1\r\n
    NullString,
    
    // Integer: :42\r\n
    Integer(u64),
}
```

**Access Methods:**
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

**Type Correspondence:**

| ValkeyObject Variant | RESP Type | Wire Format | Example |
|---------------------|-----------|-------------|---------|
| `Status(buf)` | Simple String | `+<string>\r\n` | `+OK\r\n` |
| `Error(buf)` | Error | `-<message>\r\n` | `-ERR unknown\r\n` |
| `Str(buf)` | Bulk String | `$<len>\r\n<data>\r\n` | `$5\r\nhello\r\n` |
| `Integer(n)` | Integer | `:<number>\r\n` | `:42\r\n` |
| `Array(vec)` | Array | `*<count>\r\n...` | `*2\r\n$3\r\nfoo\r\n...` |
| `NullString` | Null Bulk String | `$-1\r\n` | `$-1\r\n` |
| `NullArray` | Null Array | `*-1\r\n` | `*-1\r\n` |

---

### 3. ResponseParseResult

**Location:** `common/src/resp_response_parser_v2.rs`

**Purpose:** Indicate parsing outcome

```rust
#[derive(PartialEq, Eq, Debug)]
pub enum ResponseParseResult {
    // Not enough data to complete parsing
    NeedMoreData,
    
    // Successfully parsed: (bytes_consumed, object)
    Ok((usize, ValkeyObject)),
}
```

**Usage Flow:**
```
Buffer: [incomplete data] -> NeedMoreData
Buffer: [complete data + extra] -> Ok((consumed_bytes, object))
```

---

### 4. Statistics Models

**Location:** `sabledb-benchmark/src/stats.rs`

#### Stats Structure

```rust
#[derive(Serialize, Debug, Default)]
pub struct Stats {
    test_duration_secs: usize,    // Test duration in seconds
    total_connections: usize,      // Total connection count
    total_threads: usize,          // Total thread count
    total_requests: usize,         // Requests executed
    total_hits: usize,             // Cache hits (for GET tests)
    key_size: usize,               // Key size in bytes
    value_size: usize,             // Value size in bytes
    rps: usize,                    // Requests per second
    pipeline: usize,               // Pipeline depth used
    latency_ms: Latency,           // Latency percentiles
    options: Options,              // Full configuration snapshot
}
```

#### Latency Structure

```rust
#[derive(Serialize, Debug, Default)]
pub struct Latency {
    pmin: f64,    // Minimum latency (ms)
    p50: f64,     // Median latency (ms)
    p90: f64,     // 90th percentile (ms)
    p95: f64,     // 95th percentile (ms)
    p99: f64,     // 99th percentile (ms)
    p995: f64,    // 99.5th percentile (ms)
    p999: f64,    // 99.9th percentile (ms)
    pmax: f64,    // Maximum latency (ms)
}
```

**Global State (Lazy Static):**
```rust
lazy_static! {
    // Atomic counters for thread-safe updates
    static ref REQUESTS_PROCESSED: AtomicUsize = AtomicUsize::new(0);
    static ref HITS: AtomicUsize = AtomicUsize::new(0);
    static ref RUNNING_THREADS: AtomicUsize = AtomicUsize::new(0);
    static ref SETGET_SET_CLIENTS: AtomicUsize = AtomicUsize::new(0);
    static ref SETGET_GET_CLIENTS: AtomicUsize = AtomicUsize::new(0);
    
    // HDR histogram for latency tracking (100µs to 10 minutes)
    static ref HIST: Mutex<Histogram<u64>> 
        = Mutex::new(Histogram::<u64>::new_with_bounds(1, 600000000, 2).unwrap());
    
    // Progress bar
    static ref PROGRESS: ProgressBar = ProgressBar::new(10);
    
    // Output format flag
    static ref JSON_OUTPUT: AtomicBool = AtomicBool::new(false);
}
```

---

### 5. Connection Models

#### ValkeyClient Structure

**Location:** `sabledb-benchmark/src/valkey_client.rs`

```rust
pub struct ValkeyClient {
    stream: StreamType,              // TCP or TLS stream
    parser: RespResponseParserV2,    // Protocol parser
    leftover: BytesMut,              // Buffer for incomplete responses
}

enum StreamType {
    Plain(TcpStream),               // Plain TCP connection
    Tls(TlsStream<TcpStream>),      // TLS-encrypted connection
}
```

**State Management:**
- `stream`: Active connection (plain or encrypted)
- `parser`: Stateless parser instance
- `leftover`: Accumulates partial RESP responses across reads

#### ValkeyCluster Structure

```rust
pub struct ValkeyCluster {
    // Connection pool: "host:port" -> ValkeyClient
    connections: HashMap<String, ValkeyClient>,
    
    // Initial entry point
    initial_host: String,
    initial_port: u16,
    
    // TLS configuration
    use_tls: bool,
}
```

**Connection Pool:**
- Lazy connection creation
- Keyed by "host:port" string
- Connections persist for request lifetime
- No explicit connection pooling (one connection per task)

---

### 6. Error Models

**Location:** `common/src/errors.rs`

#### CommonError Hierarchy

```rust
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

#### ParserError Details

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
```

#### BenchmarkError

**Location:** `sabledb-benchmark/src/tests.rs`

```rust
#[derive(Error, Debug)]
enum BenchmarkError {
    #[error("I/O error. {0}")]
    StdIoError(#[from] std::io::Error),
    
    #[error("{0}")]
    UnexpectedResponse(String),
}
```

---

### 7. Request/Command Models

#### Request Structure (Internal)

**Location:** `common/src/request_parser.rs`

```rust
pub struct Request {
    pub command: Vec<BytesMut>,  // Command parts (e.g., ["SET", "key", "value"])
}
```

**RESP Array Representation:**
```
*3\r\n
$3\r\nSET\r\n
$4\r\nkey1\r\n
$5\r\nvalue\r\n

Parses to:
Request {
    command: [
        BytesMut::from("SET"),
        BytesMut::from("key1"),
        BytesMut::from("value")
    ]
}
```

---

### 8. Timing Models

#### StopWatch

**Location:** `common/src/stopwatch.rs`

```rust
#[derive(Default)]
pub struct StopWatch {
    start_time: Option<Instant>,
    end_time: Option<Instant>,
}

impl StopWatch {
    pub fn start(&mut self);
    pub fn stop(&mut self);
    pub fn elapsed_micros(&self) -> u64;
    pub fn elapsed_millis(&self) -> f64;
}
```

**Usage Pattern:**
```rust
let mut sw = StopWatch::default();
sw.start();
// ... perform operation ...
sw.stop();
let latency_us = sw.elapsed_micros();
```

---

### 9. Protocol Buffer Models

#### BytesMut Usage

**Library:** `bytes` crate

**Purpose:** Efficient, mutable byte buffer with reference counting

**Key Operations:**
```rust
// Create
let mut buf = BytesMut::new();
let mut buf = BytesMut::with_capacity(1024);
let mut buf = BytesMut::from("hello");

// Write
buf.extend_from_slice(b"data");
buf.put_u8(b'x');

// Read
let byte = buf[0];
let slice = &buf[0..5];

// Consume
buf.advance(10);  // Skip 10 bytes

// Capacity management
buf.reserve(100);
buf.clear();
```

**Benefits:**
- Zero-copy operations where possible
- Efficient for building RESP messages
- Reference-counted splitting
- Automatic capacity management

---

### 10. Cluster Models

#### Slot Calculation Model

**Slot Range:** 0-16383 (16,384 slots)

**Algorithm:**
```rust
pub fn calculate_slot(key: &[u8]) -> u16 {
    let key = match find_hashtags(key) {
        Some(tag) => tag,  // Use content between {}
        None => key,       // Use entire key
    };
    crc16::State::<crc16::XMODEM>::calculate(key) % SLOT_SIZE
}
```

**Hashtag Extraction:**
```rust
fn find_hashtags(key: &[u8]) -> Option<&[u8]> {
    // Finds first {...} pattern
    // Returns content between braces
    // Returns None if no braces or empty content
}
```

**Examples:**

| Key | Hashtag Extracted | Slot Calculated From |
|-----|-------------------|---------------------|
| `user:123` | None | `user:123` |
| `user:{123}:profile` | `{123}` | `123` |
| `{user:123}:data` | `{user:123}` | `user:123` |
| `key{}suffix` | None (empty) | `key{}suffix` |

#### MOVED Error Model

**Format:** `-MOVED <slot> <host>:<port>\r\n`

**Example:** `-MOVED 16308 127.0.0.1:7002\r\n`

**Parsing:**
```rust
fn parse_moved(errmsg: &str) -> Option<(u16, String, u16)> {
    // Returns: (slot, host, port)
}
```

#### Cluster Nodes Model

**Format (single line):**
```
<node_id> <ip>:<port>@<cport> <flags> <master> <ping_sent> <pong_recv> <config_epoch> <link_state> <slot_ranges>
```

**Parsing:**
```rust
fn parse_cluster_nodes_line(line: &str) -> Option<(String, u16)> {
    // Extracts: (ip, port)
}
```

---

## Data Flow Models

### Request Flow

```
Options
  ↓
generate_key() + generate_payload()
  ↓
RespBuilderV2::build_command()
  ↓
BytesMut (RESP-encoded)
  ↓
Connection::send_request()
  ↓
TcpStream::write_all()
```

### Response Flow

```
TcpStream::read()
  ↓
BytesMut buffer
  ↓
RespResponseParserV2::parse_response()
  ↓
ResponseParseResult::Ok(consumed, ValkeyObject)
  ↓
Test validation
  ↓
Statistics recording
```

### Cluster Routing Flow

```
RESP Request Buffer
  ↓
slot_from_buffer() → extract key → calculate_slot()
  ↓
get_or_create_connection(host, port)
  ↓
ValkeyClient::send_request()
  ↓
Response
  ↓
Check for MOVED error
  ↓ (if MOVED)
parse_moved() → retry with new node
```

---

## Memory Management

### Buffer Reuse Strategy

1. **Request Buffers:** Created per-request, cleared and reused
2. **Response Buffers:** `leftover` field accumulates partial responses
3. **Statistics:** Atomic operations avoid heap allocations
4. **Connection Pool:** HashMap maintains connections across requests

### Allocation Patterns

**Hot Path (per request):**
- BytesMut buffer allocation (amortized via capacity)
- RESP command construction
- Response parsing

**Cold Path (setup):**
- Connection establishment
- Histogram creation
- Thread spawning

---

## Serialization Models

### JSON Output (Serde)

All structures marked with `#[derive(Serialize)]`:
- `Options`
- `Stats`
- `Latency`

**Output Format:**
```json
{
  "test_duration_secs": 10,
  "total_connections": 512,
  "total_threads": 8,
  "total_requests": 1000000,
  "total_hits": 0,
  "key_size": 7,
  "value_size": 256,
  "rps": 100000,
  "pipeline": 1,
  "latency_ms": {
    "pmin": 0.1,
    "p50": 1.2,
    "p90": 2.5,
    "p95": 3.0,
    "p99": 5.0,
    "p995": 6.0,
    "p999": 8.0,
    "pmax": 10.5
  },
  "options": { ... }
}
```

---

## Configuration Data Models

### INI File Format

**File:** `$HOME/.sb.ini`

**Structure:**
```ini
[preset-name]
option1 value1
option2 value2
```

**Parsing:** Uses `rust-ini` crate

**Storage:** HashMap<String, String> in lazy_static

---

## Constants

### Protocol Constants

**Location:** `common/src/resp_builder_v2.rs`

```rust
const CRLF: &str = "\r\n";
const DOLLAR: &str = "$";
const ERR: &str = "-";
const STATUS: &str = "+";
const OK: &str = "+OK\r\n";
const EMPTY_STRING: &str = "$0\r\n\r\n";
const NULL_STRING: &str = "$-1\r\n";
const EMPTY_ARRAY: &str = "*0\r\n";
const NULL_ARRAY: &str = "*-1\r\n";
const PONG: &str = "+PONG\r\n";
```

### Cluster Constants

**Location:** `sabledb-benchmark/src/valkey_client.rs`

```rust
pub const SLOT_SIZE: u16 = 16384;  // Total number of hash slots
```

### List Test Constants

**Location:** `sabledb-benchmark/src/main.rs`

```rust
const LIST_KEY_RANGE: usize = 1000;  // Reduced key range for list tests
```

---

## Type Aliases and Wrappers

### Common Utility Types

```rust
pub struct StringUtils {}    // String manipulation utilities
pub struct BytesMutUtils {}  // BytesMut helper functions
pub struct TimeUtils {}      // Time-related utilities
```

These are primarily namespaces for utility functions rather than data carriers.
