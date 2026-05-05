# AGENTS.md - AI Coding Assistant Guide for sb (SableDB Benchmark)

**Version:** 1.0  
**Project:** sb - A modern drop-in replacement for Valkey/Redis benchmark tool  
**Language:** Rust (Edition 2021)  
**Architecture:** Multi-threaded async I/O benchmark framework

---

## Quick Start for AI Assistants

### Project Purpose
`sb` is a high-performance benchmarking tool for Valkey/Redis-compatible servers. It provides comprehensive testing of various commands (SET, GET, PING, INCR, list operations, hash operations, and vector DB ingestion) with support for single-node and cluster deployments.

### Key Entry Points
- **Binary Entry:** `sabledb-benchmark/src/main.rs` - Application startup and thread orchestration
- **CLI Options:** `sabledb-benchmark/src/sb_options.rs` - Command-line configuration
- **Test Suite:** `sabledb-benchmark/src/tests.rs` - All benchmark test implementations
- **Networking:** `sabledb-benchmark/src/valkey_client.rs` - Connection management
- **Protocol:** `common/src/resp_builder_v2.rs` and `common/src/resp_response_parser_v2.rs` - RESP protocol handling

---

## Directory Structure & Navigation

```
benchmark/
├── common/                    # Shared library (sbcommonlib)
│   ├── src/
│   │   ├── errors.rs         # Error type definitions
│   │   ├── resp_builder_v2.rs      # RESP protocol message builder
│   │   ├── resp_response_parser_v2.rs  # RESP protocol response parser
│   │   ├── request_parser.rs       # Request parsing for cluster routing
│   │   ├── stopwatch.rs      # High-precision timing
│   │   ├── pattern_matcher.rs      # Glob pattern matching
│   │   ├── file_utils.rs     # File operations
│   │   ├── ticker.rs         # Periodic operations
│   │   └── lib.rs            # Module exports
│   └── Cargo.toml            # Common library dependencies
│
├── sabledb-benchmark/         # Main application (sb)
│   ├── src/
│   │   ├── main.rs           # Entry point, thread management
│   │   ├── sb_options.rs     # CLI parsing, configuration
│   │   ├── tests.rs          # All benchmark tests
│   │   ├── valkey_client.rs  # Single-node & cluster clients
│   │   ├── stats.rs          # Statistics collection & reporting
│   │   ├── bench_utils.rs    # Key/payload generation
│   │   └── build.rs          # Platform-specific build config
│   └── Cargo.toml            # Application dependencies
│
├── .agents/summary/           # AI documentation (auto-generated)
│   ├── index.md              # Knowledge base index (START HERE)
│   ├── architecture.md       # System design & patterns
│   ├── components.md         # Module documentation
│   ├── interfaces.md         # APIs & interfaces
│   ├── data_models.md        # Data structures
│   ├── workflows.md          # Execution flows
│   ├── dependencies.md       # External libraries
│   └── review_notes.md       # Documentation quality notes
│
├── Cargo.toml                # Workspace configuration
├── Cargo.lock                # Dependency lock file
└── README.md                 # User documentation
```

---

## Major Subsystems

### 1. CLI & Configuration System
**Location:** `sabledb-benchmark/src/sb_options.rs`

**Responsibilities:**
- Parse command-line arguments using `clap`
- Load preset configurations from `~/.sb.ini`
- Validate and finalize options
- Calculate derived values (key size, requests per connection)

**Key Types:**
- `Options` struct - All configuration options
- Preset system - Named configuration profiles

**Common Tasks:**
- Adding new CLI options: Modify `Options` struct with `#[arg(...)]` attributes
- Changing defaults: Update `default_value` in struct field attributes
- Adding presets: Users edit `~/.sb.ini` file

### 2. Thread & Task Orchestration
**Location:** `sabledb-benchmark/src/main.rs`

**Architecture:**
- N OS threads (configurable via `--threads`)
- Each thread runs a Tokio current-thread runtime
- M async tasks per thread (connections / threads)
- Tasks execute on `LocalSet` for performance

**Flow:**
1. `main()` - Parse args, setup logging, spawn threads
2. `thread_main()` - Create runtime, spawn tasks
3. `task_main()` - Establish connection, run test
4. Aggregate results in main thread

**Special Case:** SETGET test splits connections into separate SET and GET task pools based on ratio

### 3. Network Layer
**Location:** `sabledb-benchmark/src/valkey_client.rs`

**Two Connection Types:**

#### ValkeyClient (Single-Node)
- Direct TCP/TLS connection to one server
- Simple request-response pattern
- Suitable for standalone Redis/Valkey

#### ValkeyCluster (Cluster-Aware)
- Manages connection pool (lazy initialization)
- CRC16-based slot calculation (0-16383)
- Hashtag support for key routing (`{tag}`)
- Automatic MOVED/ASK redirection handling
- Dynamic node discovery

**Key Functions:**
- `calculate_slot(key)` - Determines cluster slot for a key
- `get_or_create_connection()` - Lazy connection pooling
- `send_request()` - Common interface for both types

### 4. RESP Protocol Layer
**Location:** `common/src/`

#### Request Building (`resp_builder_v2.rs`)
```rust
let builder = RespBuilderV2::default();
builder.add_array_len(&mut buffer, 3);
builder.add_bulk_string(&mut buffer, b"SET");
builder.add_bulk_string(&mut buffer, key);
builder.add_bulk_string(&mut buffer, value);
// Result: *3\r\n$3\r\nSET\r\n$<len>\r\n<key>\r\n$<len>\r\n<value>\r\n
```

#### Response Parsing (`resp_response_parser_v2.rs`)
- Handles partial responses (returns `NeedMoreData`)
- Supports all RESP v2 types: Status, Error, Integer, Bulk String, Array
- Recursive array parsing
- Returns `ValkeyObject` enum

### 5. Test Framework
**Location:** `sabledb-benchmark/src/tests.rs`

**All tests follow this pattern:**
```rust
pub async fn run_test(
    mut conn: impl Connection,
    opts: Options,
    requests_count: usize
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Setup (builders, stopwatch, buffers)
    // 2. Loop for requests_count:
    //    a. Generate key/payload
    //    b. Build RESP command
    //    c. Start timer, send request, stop timer
    //    d. Parse and validate response
    //    e. Record latency and update stats
    // 3. Return
}
```

**Supported Tests:**
- `run_set` / `run_get` - Basic key-value operations
- `run_incr` - Counter increments
- `run_ping` - Connectivity test
- `run_push` / `run_pop` - List operations (left/right)
- `run_hset` - Hash operations
- `run_vecdb_ingest` - Vector database ingestion (FT.ADD)

**Adding New Test:**
1. Add function in `tests.rs` following the pattern above
2. Add match arm in `task_main()` in `main.rs`
3. Update CLI help in `sb_options.rs`

### 6. Statistics & Monitoring
**Location:** `sabledb-benchmark/src/stats.rs`

**Design:**
- Lock-free atomic counters for high performance
- HDR histogram for latency (100µs to 10 minutes range)
- Real-time progress bars via `indicatif`
- Optional JSON output

**Global State (lazy_static):**
- `REQUESTS_PROCESSED` - Atomic counter
- `HITS` - Cache hits for GET tests
- `HIST` - Mutex-protected HDR histogram
- `PROGRESS` - Progress bar instance

**Key Functions:**
- `record_latency(micros)` - Add latency sample
- `incr_requests_processed(count)` - Update counter
- `Stats::collect()` - Generate final report

---

## Repo-Specific Patterns

### Pattern 1: Connection Trait Abstraction
Both `ValkeyClient` and `ValkeyCluster` implement the `Connection` trait:
```rust
#[async_trait]
pub trait Connection {
    async fn send_request(&mut self, buffer: &[u8]) 
        -> Result<BytesMut, CommonError>;
}
```
This allows test functions to be generic over connection type, enabling seamless single-node vs cluster testing.

### Pattern 2: BytesMut for Zero-Copy
The codebase heavily uses `BytesMut` from the `bytes` crate:
- Request building reuses buffers (`buffer.clear()`)
- Response accumulation in `leftover` field
- Efficient slicing without copying

### Pattern 3: StopWatch for Latency Measurement
```rust
let sw = StopWatch::default();
sw.start();
// ... operation ...
sw.stop();
stats::record_latency(sw.elapsed_micros());
```
Consistent timing pattern across all tests ensures accurate latency tracking.

### Pattern 4: Lazy Static for Global State
Used for statistics, presets, and configuration:
```rust
lazy_static! {
    static ref COUNTER: AtomicUsize = AtomicUsize::new(0);
}
```
Enables lock-free updates from multiple threads.

### Pattern 5: Builder Pattern for RESP
Protocol messages are built incrementally:
```rust
builder.add_array_len(&mut buffer, n);
for arg in args {
    builder.add_bulk_string(&mut buffer, arg);
}
```

---

## Non-Standard Approaches & Deviations

### TLS Certificate Validation Disabled
**Why:** Benchmarking tool prioritizes performance over security validation
**Implementation:** Custom `NoVerifier` struct bypasses all certificate checks
**Warning:** Do NOT use this pattern in production applications

### Ctrl+C Handler Calls exit(0)
**Why:** Immediate shutdown for benchmark tool
**Impact:** No graceful cleanup of in-flight requests
**Location:** `main.rs` - `ctrlc::set_handler()`

### Current-Thread Runtime (Not Multi-Thread)
**Why:** Avoids thread migration overhead, better for benchmark accuracy
**Impact:** Each worker thread runs isolated Tokio runtime
**Benefit:** Better CPU cache locality, more predictable performance

### Single Codegen Unit in Release
**Why:** Maximizes optimization across the entire binary
**Trade-off:** Slower compile times for better runtime performance
**Config:** `Cargo.toml` - `[profile.release]`

---

## Configuration Files & Discovery

### Cargo Workspace (`Cargo.toml` at root)
```toml
[workspace]
members = ["common", "sabledb-benchmark"]
resolver = "2"

[profile.release]
lto = true              # Link-time optimization
codegen-units = 1       # Single unit for max optimization
strip = "symbols"       # Strip debug symbols
```

### Preset Configuration (`$HOME/.sb.ini`)
```ini
[preset-name]
--option1 value1
--option2 value2
```
Users can store reusable test configurations and invoke with `sb --preset preset-name`

### Build Script (`sabledb-benchmark/build.rs`)
Windows-specific: Links pthread library
```rust
#[cfg(target_os = "windows")]
fn main() {
    println!("cargo:rustc-link-lib=pthread");
}
```

---

## Testing Approach

### Unit Tests
- Located within source files using `#[cfg(test)]` modules
- Example in `bench_utils.rs` - vector generation test
- Use `test-case` crate for parameterized tests

### Integration Tests
- No separate integration test directory
- Main binary serves as integration test vehicle

### Running Tests
```bash
cargo test              # Run all tests
cargo test --lib        # Library tests only
cargo test --bin sb     # Binary tests only
```

---

## Build & Development

### Building
```bash
cargo build             # Debug build
cargo build --release   # Optimized release build
```

### Running
```bash
cargo run -- [OPTIONS]
# or after build:
target/release/sb [OPTIONS]
```

### Common Dev Commands
```bash
cargo check             # Fast compile check
cargo clippy            # Linting
cargo fmt               # Format code
cargo doc --open        # Generate & open docs
```

---

## Key Dependencies & Usage

### Critical Runtime Dependencies
- `tokio` (full features) - Async runtime, all I/O operations
- `bytes` - All buffer management, protocol handling
- `hdrhistogram` - Latency percentile calculation
- `clap` (derive) - All CLI parsing

### Protocol & Networking
- `tokio-rustls` / `rustls` - TLS support (with custom verifier)
- `crc16` - Cluster slot calculation

### Output & Display
- `indicatif` - Progress bars
- `serde` / `serde_json` - JSON output
- `colored` - Terminal colors

### Utilities
- `lazy_static` - Global state initialization
- `thiserror` - Error type definitions
- `rand` - Random data generation
- `rust-ini` - Preset file parsing

---

## Common Development Tasks

### Adding a New CLI Option
1. Add field to `Options` struct in `sb_options.rs`
2. Add `#[arg(...)]` attribute with configuration
3. Update `finalise()` if derived calculations needed
4. Update README.md with new option

### Adding a New Test Type
1. Implement `run_newtest()` in `tests.rs`
2. Follow existing pattern (see "Test Framework" section)
3. Add match arm in `task_main()` in `main.rs`
4. Update help text and README

### Modifying RESP Protocol
1. For requests: Extend `RespBuilderV2` in `common/src/resp_builder_v2.rs`
2. For responses: Extend `ValkeyObject` enum and parser in `common/src/resp_response_parser_v2.rs`
3. Update tests to validate new behavior

### Changing Statistics
1. Add counter: Add `AtomicUsize` to lazy_static in `stats.rs`
2. Add histogram metric: Modify `HIST` recording
3. Add output field: Update `Stats` struct and `collect()` method
4. For JSON: Ensure field is `Serialize`-able

### Debugging Connection Issues
1. Enable debug logging: `--log-level debug`
2. Check `valkey_client.rs` connection establishment
3. For cluster: Verify slot calculation with `calculate_slot()`
4. Use `tracing::debug!()` to add temporary logging

---

## Gotchas & Common Pitfalls

### 1. Key Range for List Operations
List operations (`lpush`, `rpop`, etc.) hard-code `LIST_KEY_RANGE = 1000` to avoid memory exhaustion. Don't use with large `--key-range` values.

### 2. SETGET Ratio Parsing
Format is "X:Y" (e.g., "1:4"). Parser splits on colon and converts to floats. Invalid format causes panic.

### 3. Cluster Slot Calculation with Hashtags
Keys with `{tag}` only use the content between braces for slot calculation. Empty braces fallback to full key.

### 4. TLS Certificate Errors Ignored
All certificate validation errors are intentionally ignored. Don't debug cert issues - it's by design for benchmarking.

### 5. Progress Bar Updates Are Batched
Calling `update_progress(1)` per request batches updates internally for performance. May appear laggy.

### 6. Connection Pool is Per-Task
Each async task maintains its own connection. No sharing between tasks. Cluster client's pool is per-task instance.

### 7. BytesMut Capacity Management
Must call `buffer.clear()` to reuse, not just `buffer = BytesMut::new()` in hot loops.

### 8. Atomic Operations Ordering
Most atomics use `Ordering::Relaxed` for performance. Strong ordering not needed for statistics.

---

## Performance Considerations

### Hot Paths
1. Request/response cycle in test functions
2. RESP protocol building and parsing
3. Statistics recording (atomic increments)
4. Key/payload generation

### Optimization Strategies
- Buffer reuse via `clear()` instead of allocating
- Atomic operations with `Relaxed` ordering
- Current-thread runtime avoids context switches
- LocalSet prevents task migration
- Single codegen unit enables cross-function optimization

### Scaling Parameters
- `--threads` - Add more OS threads (saturate CPU cores)
- `--connections` - More concurrent connections
- `--pipeline` - Batch requests (note: current impl is simple)
- Reduce `--num-requests` for faster tests

---

## Documentation Resources

### Auto-Generated Knowledge Base
Located in `.agents/summary/`:
- **Start with:** `index.md` - Navigation guide
- **Architecture:** `architecture.md` - System design
- **Components:** `components.md` - Module details
- **APIs:** `interfaces.md` - Public interfaces
- **Data:** `data_models.md` - Structures and types
- **Flows:** `workflows.md` - Execution sequences
- **Deps:** `dependencies.md` - External libraries

### Reading Code
- Start at `main.rs` for application flow
- `tests.rs` for understanding benchmark patterns
- `valkey_client.rs` for network layer
- `resp_*.rs` files for protocol details
- `stats.rs` for metrics collection

---

## Custom Instructions

<!-- This section is maintained by developers and agents during day-to-day work.
     It is NOT auto-generated by codebase-summary and MUST be preserved during refreshes.
     Add project-specific conventions, gotchas, and workflow requirements here. -->

