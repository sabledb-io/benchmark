# System Architecture

## Architectural Overview

The `sb` benchmark tool follows a multi-layered architecture designed for high-performance, concurrent benchmarking of Valkey/Redis-compatible servers.

```mermaid
graph TB
    CLI[CLI Interface<br/>sb_options] --> Main[Main Orchestrator<br/>main.rs]
    Main --> ThreadPool[Thread Pool]
    ThreadPool --> Thread1[Worker Thread 1]
    ThreadPool --> Thread2[Worker Thread 2]
    ThreadPool --> ThreadN[Worker Thread N]
    
    Thread1 --> LocalSet1[Tokio LocalSet]
    Thread2 --> LocalSet2[Tokio LocalSet]
    ThreadN --> LocalSetN[Tokio LocalSet]
    
    LocalSet1 --> Task1_1[Async Task]
    LocalSet1 --> Task1_2[Async Task]
    LocalSet2 --> Task2_1[Async Task]
    LocalSet2 --> Task2_2[Async Task]
    
    Task1_1 --> Client1[ValkeyClient/<br/>ValkeyCluster]
    Task1_2 --> Client2[ValkeyClient/<br/>ValkeyCluster]
    Task2_1 --> Client3[ValkeyClient/<br/>ValkeyCluster]
    
    Client1 --> Tests[Test Runners]
    Client2 --> Tests
    Client3 --> Tests
    
    Tests --> Stats[Statistics Collector]
    Stats --> Output[Progress Bar/<br/>JSON Output]
    
    Client1 -.RESP Protocol.-> Server[(Valkey/Redis<br/>Server)]
    Client2 -.RESP Protocol.-> Server
    Client3 -.RESP Protocol.-> Server
    
    CommonLib[Common Library<br/>sbcommonlib] --> Tests
    CommonLib --> Client1
    CommonLib --> Client2
    CommonLib --> Client3
    
    style CLI fill:#e1f5ff
    style Main fill:#fff4e1
    style CommonLib fill:#e8f5e9
    style Stats fill:#fce4ec
    style Server fill:#f3e5f5
```

## Architectural Patterns

### 1. **Layered Architecture**

The system is organized into distinct layers:

- **Presentation Layer** - CLI interface with argument parsing
- **Application Layer** - Test orchestration and coordination
- **Business Logic Layer** - Test implementations and benchmark logic
- **Protocol Layer** - RESP protocol handling (builder/parser)
- **Transport Layer** - Network I/O with TLS support

### 2. **Concurrent Task Model**

```mermaid
graph LR
    Main[Main Process] --> T1[Thread 1]
    Main --> T2[Thread 2]
    Main --> TN[Thread N]
    
    T1 --> RT1[Tokio Runtime]
    T2 --> RT2[Tokio Runtime]
    TN --> RTN[Tokio Runtime]
    
    RT1 --> LS1[LocalSet]
    RT2 --> LS2[LocalSet]
    RTN --> LSN[LocalSet]
    
    LS1 --> AT1[Async Task 1]
    LS1 --> AT2[Async Task 2]
    LS1 --> ATM[Async Task M]
    
    AT1 --> Conn1[Connection 1]
    AT2 --> Conn2[Connection 2]
    ATM --> ConnM[Connection M]
    
    style Main fill:#ffeb3b
    style RT1 fill:#81c784
    style LS1 fill:#4fc3f7
    style AT1 fill:#ba68c8
```

**Key Characteristics:**
- N OS threads (configurable via `--threads`)
- Each thread runs a dedicated Tokio current-thread runtime
- Tasks run on `LocalSet` for better performance (no thread synchronization)
- M connections per thread (calculated as `connections / threads`)
- Each async task manages one TCP connection

### 3. **Plugin-Style Test Architecture**

Tests are implemented as independent modules that follow a common pattern:

```rust
async fn run_test(
    conn: impl Connection,
    opts: Options,
    requests_count: usize
) -> Result<(), Box<dyn std::error::Error>>
```

This allows easy addition of new benchmark types without modifying core infrastructure.

## Core Components

### Main Orchestrator (`main.rs`)

**Responsibilities:**
- Parse command-line arguments
- Initialize logging and statistics
- Spawn worker threads
- Wait for completion and report results

**Flow:**
1. Parse CLI options (with preset support)
2. Configure logging level
3. Initialize statistics and progress tracking
4. Spawn N worker threads
5. Each thread spawns M async tasks
6. Wait for all threads to complete
7. Report aggregated statistics

### Thread Management

```mermaid
sequenceDiagram
    participant Main
    participant Thread
    participant TokioRT
    participant LocalSet
    participant Task
    participant Stats
    
    Main->>Thread: spawn()
    Thread->>TokioRT: create current_thread runtime
    TokioRT->>LocalSet: spawn LocalSet
    
    loop For each connection
        LocalSet->>Task: spawn_local(task_main)
        Task->>Task: run benchmark
        Task->>Stats: update metrics
    end
    
    Task-->>LocalSet: complete
    LocalSet-->>TokioRT: await
    TokioRT-->>Thread: done
    Thread->>Stats: decr_threads_running()
    Thread-->>Main: join
    
    Main->>Stats: collect & report
```

### Connection Abstraction

Two connection types are provided through a common trait:

1. **ValkeyClient** - Single-node connection
2. **ValkeyCluster** - Cluster-aware connection with slot routing

Both implement the `Connection` trait:

```rust
#[async_trait]
pub trait Connection {
    async fn send_request(&mut self, buffer: &[u8]) -> Result<BytesMut, CommonError>;
    async fn send_vecdb_ingest_request(&mut self, requests: Vec<BytesMut>) -> Result<Vec<BytesMut>, CommonError>;
}
```

### Cluster Architecture

```mermaid
graph TB
    Client[ValkeyCluster Client]
    Client --> SlotCalc[Slot Calculator<br/>CRC16 based]
    Client --> ConnPool[Connection Pool<br/>HashMap by Address]
    
    SlotCalc --> Slot[Slot: 0-16383]
    
    ConnPool --> Node1[Node 1<br/>127.0.0.1:7000]
    ConnPool --> Node2[Node 2<br/>127.0.0.1:7001]
    ConnPool --> Node3[Node 3<br/>127.0.0.1:7002]
    
    Node1 -.MOVED.-> HandleRedirect[Handle Redirect]
    HandleRedirect --> UpdateSlotMap[Update Slot Mapping]
    UpdateSlotMap --> Retry[Retry Request]
    
    style Client fill:#e3f2fd
    style SlotCalc fill:#fff3e0
    style ConnPool fill:#e8f5e9
    style HandleRedirect fill:#fce4ec
```

**Cluster Features:**
- Slot calculation using CRC16 (XMODEM variant)
- Hashtag support for key grouping
- Lazy connection establishment
- MOVED/ASK redirection handling
- Dynamic node discovery

## Protocol Architecture

### RESP Protocol Stack

```mermaid
graph LR
    subgraph Outbound
        Request[Request Data] --> Builder[RespBuilderV2]
        Builder --> Buffer[BytesMut Buffer]
        Buffer --> TCP[TCP Stream]
    end
    
    subgraph Inbound
        TCP2[TCP Stream] --> Parser[RespResponseParserV2]
        Parser --> Object[ValkeyObject]
        Object --> Test[Test Logic]
    end
    
    style Builder fill:#81c784
    style Parser fill:#4fc3f7
```

**Components:**
1. **RespBuilderV2** - Constructs RESP protocol messages
2. **RespResponseParserV2** - Parses RESP responses into structured objects
3. **ValkeyObject** - Enum representing RESP data types
4. **RequestParser** - Parses RESP requests (for slot calculation)

**Supported RESP Types:**
- Simple Strings (Status)
- Errors
- Integers
- Bulk Strings
- Arrays
- Null values

## Statistics & Monitoring Architecture

```mermaid
graph TB
    Tasks[Async Tasks] --> Counters[Atomic Counters]
    Tasks --> Histogram[HDR Histogram<br/>Latency Tracking]
    
    Counters --> ReqProcessed[Requests Processed]
    Counters --> Hits[Cache Hits]
    Counters --> Threads[Running Threads]
    
    Histogram --> Percentiles[Percentiles:<br/>p50, p90, p95, p99, p999]
    
    Counters --> Aggregator[Stats Collector]
    Histogram --> Aggregator
    Options[Options] --> Aggregator
    
    Aggregator --> Progress[Progress Bar]
    Aggregator --> JSON[JSON Output]
    
    style Counters fill:#fff9c4
    style Histogram fill:#f8bbd0
    style Aggregator fill:#c5e1a5
```

**Statistics Features:**
- Lock-free atomic counters for high-performance updates
- HDR histogram for accurate latency percentiles (100µs to 10 minutes range)
- Real-time progress bars using `indicatif`
- Optional JSON output for machine processing
- Per-test-type tracking (SET vs GET in setget mode)

## Data Flow

### Request Flow

```mermaid
sequenceDiagram
    participant Test as Test Runner
    participant Utils as bench_utils
    participant Builder as RespBuilderV2
    participant Client as Connection
    participant SW as StopWatch
    participant Stats as Statistics
    
    Test->>Utils: generate_key()
    Utils-->>Test: key
    Test->>Utils: generate_payload()
    Utils-->>Test: payload
    
    Test->>Builder: build RESP command
    Builder-->>Test: buffer
    
    Test->>SW: start()
    Test->>Client: send_request(buffer)
    Client-->>Test: response
    Test->>SW: stop()
    
    Test->>Stats: record_latency(duration)
    Test->>Stats: incr_requests_processed()
    
    Test->>Test: repeat
```

### Response Flow

```mermaid
sequenceDiagram
    participant Client as Connection
    participant TCP as TCP Stream
    participant Parser as RespResponseParserV2
    participant Test as Test Runner
    
    Client->>TCP: read_bytes()
    TCP-->>Client: raw_buffer
    
    Client->>Parser: parse_response(buffer)
    
    alt Complete Response
        Parser-->>Client: Ok(ValkeyObject)
        Client-->>Test: Ok(response)
    else Need More Data
        Parser-->>Client: NeedMoreData
        Client->>TCP: read_more_bytes()
        TCP-->>Client: more_data
        Client->>Parser: parse_response(buffer)
    end
```

## Configuration Architecture

### Preset System

```mermaid
graph LR
    User[User] --> CLI{CLI Args}
    CLI -->|--preset name| Loader[Preset Loader]
    CLI -->|direct args| Parser[Arg Parser]
    
    Loader --> INI[$HOME/.sb.ini]
    INI --> Parser
    
    Parser --> Options[Options Struct]
    Options --> Validate[Validation]
    Validate --> Finalize[Finalize]
    
    Finalize --> Main[Main Execution]
    
    style INI fill:#fff3e0
    style Options fill:#e1f5fe
    style Finalize fill:#c8e6c9
```

**Preset Features:**
- INI file format for easy editing
- Named presets for common scenarios
- Override capability with CLI args
- Stored in user home directory

## Error Handling Architecture

### Error Type Hierarchy

```mermaid
classDiagram
    class CommonError {
        +InvalidArgument(String)
        +OtherError(String)
        +Parser(ParserError)
        +StdIoError(io::Error)
    }
    
    class ParserError {
        +NeedMoreData
        +ProtocolError(String)
        +BufferTooBig
        +Overflow
        +InvalidInput(String)
    }
    
    class BenchmarkError {
        +StdIoError(io::Error)
        +UnexpectedResponse(String)
    }
    
    CommonError --> ParserError : contains
    BenchmarkError --> CommonError : uses
    
    style CommonError fill:#ffcdd2
    style ParserError fill:#f8bbd0
    style BenchmarkError fill:#ffccbc
```

## Security Architecture

### TLS Support

```mermaid
graph TB
    Client[Client] --> TLSCheck{TLS Enabled?}
    TLSCheck -->|No| PlainTCP[Plain TCP Connection]
    TLSCheck -->|Yes| TLSConfig[TLS Configuration]
    
    TLSConfig --> NoVerifier[NoVerifier<br/>Skip Certificate Check]
    NoVerifier --> Handshake[TLS Handshake]
    Handshake --> TLSStream[TLS Stream]
    
    PlainTCP --> ReadWrite[Read/Write Operations]
    TLSStream --> ReadWrite
    
    style TLSConfig fill:#b2dfdb
    style NoVerifier fill:#ffcc80
    style TLSStream fill:#a5d6a7
```

**Security Notes:**
- TLS certificate verification is intentionally bypassed for benchmarking
- Uses `tokio-rustls` for async TLS support
- Supports both `--tls` and `--ssl` flags

## Scalability Considerations

### Thread Scaling

- **Horizontal Scaling:** Add more threads (`--threads`)
- **Connection Scaling:** Increase connections (`--connections`)
- **Request Scaling:** Configure total requests (`--num-requests`)

### Optimization Strategies

1. **Current-thread Runtime:** Avoids thread synchronization overhead
2. **LocalSet:** Tasks don't migrate between threads
3. **Lock-free Statistics:** Atomic operations for counters
4. **Buffer Reuse:** BytesMut for efficient buffer management
5. **Release Profile:** LTO and single codegen unit

## Extension Points

### Adding New Tests

1. Implement test function in `tests.rs`:
   ```rust
   pub async fn run_mytest(
       conn: impl Connection,
       opts: Options,
       requests_count: usize
   ) -> Result<(), Box<dyn std::error::Error>>
   ```

2. Add test name to match statement in `task_main()` in `main.rs`

3. Update CLI help text in `sb_options.rs`

### Adding Protocol Extensions

1. Extend `ValkeyObject` enum in `resp_response_parser_v2.rs`
2. Update parser to handle new type
3. Update builder if needed for outbound messages

## Design Principles

1. **Separation of Concerns** - Protocol, transport, and business logic are distinct
2. **Async-First** - Built on Tokio for efficient I/O
3. **Zero-Copy Where Possible** - BytesMut avoids unnecessary allocations
4. **Fail-Fast** - Clear error types with thiserror
5. **Observability** - Comprehensive statistics and progress tracking
6. **Flexibility** - Configurable parameters for various workload patterns
7. **Performance** - Lock-free design, efficient protocols, optimized builds
