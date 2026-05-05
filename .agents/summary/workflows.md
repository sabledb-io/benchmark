# Key Workflows and Processes

## Application Lifecycle

### 1. Startup and Initialization

```mermaid
sequenceDiagram
    participant User
    participant Main
    participant CLI
    participant Stats
    participant Logger
    participant CtrlC
    
    User->>Main: Run sb binary
    Main->>CLI: Parse arguments
    
    alt Preset specified
        CLI->>CLI: Load ~/.sb.ini
        CLI->>CLI: Parse preset section
    end
    
    CLI-->>Main: Options struct
    Main->>Main: Finalize options
    Main->>Stats: Configure JSON output
    Main->>Logger: Initialize tracing
    Main->>CtrlC: Setup signal handler
    Main->>Stats: Setup progress bar
    Main->>Main: Display configuration
```

**Steps:**

1. **Argument Parsing** (`Options::initialise()`)
   - Parse command-line with clap
   - If `--preset` specified, load INI file
   - Merge preset with CLI overrides
   - Return (Options, command_line_string)

2. **Finalization** (`Options::finalise()`)
   - Calculate derived fields (key_size, etc.)
   - Validate option combinations
   - Parse setget ratio if needed
   - Extract vector DB configuration

3. **Logging Setup**
   - Configure `tracing_subscriber`
   - Set log level from options
   - Enable thread names and IDs

4. **Statistics Initialization**
   - Configure output format (JSON vs human)
   - Setup progress bar with total request count
   - Initialize atomic counters

5. **Signal Handling**
   - Install Ctrl+C handler
   - Allows graceful shutdown

---

### 2. Thread Orchestration Workflow

```mermaid
sequenceDiagram
    participant Main
    participant Thread1
    participant Thread2
    participant Stats
    
    Main->>Stats: Set threads_running = N
    
    par Thread Spawning
        Main->>Thread1: spawn worker thread
        Main->>Thread2: spawn worker thread
    end
    
    Thread1->>Thread1: Create Tokio runtime
    Thread2->>Thread2: Create Tokio runtime
    
    Thread1->>Thread1: Spawn M async tasks
    Thread2->>Thread2: Spawn M async tasks
    
    Note over Thread1: Execute benchmarks
    Note over Thread2: Execute benchmarks
    
    Thread1->>Stats: decr_threads_running()
    Thread2->>Stats: decr_threads_running()
    
    Thread1-->>Main: join()
    Thread2-->>Main: join()
    
    Main->>Stats: Collect final statistics
    Main->>Main: Display results
```

**Thread Distribution:**

Given:
- N = total threads
- C = total connections
- R = total requests

Calculations:
- Connections per thread: `C / N`
- Requests per connection: `R / C`

Example:
- 8 threads, 512 connections, 1,000,000 requests
- Each thread: 64 connections
- Each connection: ~1,953 requests

---

### 3. Task Execution Workflow

```mermaid
flowchart TB
    Start[Task Start] --> CheckTest{Test Type}
    
    CheckTest -->|setget| SplitTasks[Split into SET/GET tasks]
    CheckTest -->|other| SingleTask[Single task type]
    
    SplitTasks --> CalcRatio[Calculate SET:GET ratio]
    CalcRatio --> SpawnSet[Spawn SET tasks]
    CalcRatio --> SpawnGet[Spawn GET tasks]
    
    SingleTask --> SpawnTasks[Spawn N tasks]
    
    SpawnSet --> TaskMain1[task_main]
    SpawnGet --> TaskMain2[task_main]
    SpawnTasks --> TaskMain3[task_main]
    
    TaskMain1 --> Connect1[Establish Connection]
    TaskMain2 --> Connect2[Establish Connection]
    TaskMain3 --> Connect3[Establish Connection]
    
    Connect1 --> RunTest1[Run Test Function]
    Connect2 --> RunTest2[Run Test Function]
    Connect3 --> RunTest3[Run Test Function]
    
    RunTest1 --> Complete1[Task Complete]
    RunTest2 --> Complete2[Task Complete]
    RunTest3 --> Complete3[Task Complete]
    
    Complete1 --> Await[LocalSet.await]
    Complete2 --> Await
    Complete3 --> Await
    
    Await --> ThreadDone[Thread Done]
```

**Special Case: SETGET Test**

For `--test setget --setget-ratio 1:4`:

1. Parse ratio: SET=1, GET=4
2. Calculate multipliers:
   - SET multiplier = 1/(1+4) = 0.2
   - GET multiplier = 4/(1+4) = 0.8
3. If 64 connections:
   - SET tasks = floor(64 × 0.2) = 12
   - GET tasks = ceil(64 × 0.8) = 52
4. Spawn separate task sets with different test types

---

### 4. Connection Establishment Workflow

#### Single-Node Connection

```mermaid
sequenceDiagram
    participant Task
    participant Client
    participant TCP
    participant TLS
    participant Server
    
    Task->>Client: ValkeyClient::connect(host, port, use_tls)
    
    Client->>TCP: TcpStream::connect()
    TCP-->>Client: TcpStream
    
    alt TLS Enabled
        Client->>TLS: Create TLS connector
        Client->>TLS: Perform handshake
        TLS->>Server: TLS negotiation
        Server-->>TLS: Accept
        TLS-->>Client: TlsStream
        Client->>Client: StreamType::Tls
    else Plain
        Client->>Client: StreamType::Plain
    end
    
    Client-->>Task: ValkeyClient instance
```

#### Cluster Connection

```mermaid
sequenceDiagram
    participant Task
    participant Cluster
    participant Server
    participant Client
    
    Task->>Cluster: ValkeyCluster::connect(host, port, use_tls)
    Cluster->>Cluster: Store initial_host, initial_port
    Cluster->>Cluster: Initialize empty connection pool
    Cluster-->>Task: ValkeyCluster instance
    
    Note over Task,Cluster: Connections created lazily on first request
    
    Task->>Cluster: send_request(buffer)
    Cluster->>Cluster: calculate_slot(key)
    Cluster->>Cluster: get_or_create_connection(host, port)
    
    alt Connection exists
        Cluster->>Cluster: Return existing
    else New connection
        Cluster->>Client: ValkeyClient::connect()
        Client-->>Cluster: New connection
        Cluster->>Cluster: Store in pool
    end
    
    Cluster->>Client: Forward request
    Client->>Server: Send via TCP
```

---

### 5. Benchmark Test Execution Workflow

#### Generic Test Pattern

```mermaid
flowchart TB
    Start[Start Test] --> Init[Initialize]
    Init --> GenerateKey[Generate Key]
    GenerateKey --> GeneratePayload[Generate Payload]
    GeneratePayload --> BuildReq[Build RESP Request]
    
    BuildReq --> StartTimer[Start StopWatch]
    StartTimer --> SendReq[Send Request]
    SendReq --> ReadResp[Read Response]
    ReadResp --> StopTimer[Stop StopWatch]
    
    StopTimer --> Parse[Parse Response]
    Parse --> Validate[Validate Response]
    
    Validate -->|Error| LogError[Log Error]
    Validate -->|OK| RecordLatency[Record Latency]
    
    RecordLatency --> IncrStats[Increment Stats]
    IncrStats --> UpdateProgress[Update Progress]
    
    UpdateProgress --> CheckCount{More Requests?}
    CheckCount -->|Yes| GenerateKey
    CheckCount -->|No| Finish[Finish]
    
    LogError --> CheckCount
```

#### Example: SET Test Workflow

```rust
async fn run_set(
    mut conn: impl Connection,
    opts: Options,
    requests_count: usize
) -> Result<(), Box<dyn std::error::Error>> {
    let builder = RespBuilderV2::default();
    let mut buffer = BytesMut::new();
    let sw = StopWatch::default();
    
    for _ in 0..requests_count {
        // 1. Generate test data
        let key = bench_utils::generate_key(
            opts.get_key_size(),
            opts.key_range
        );
        let value = bench_utils::generate_payload(opts.data_size);
        
        // 2. Build RESP command
        buffer.clear();
        builder.add_array_len(&mut buffer, 3);
        builder.add_bulk_string(&mut buffer, b"SET");
        builder.add_bulk_string(&mut buffer, &key);
        builder.add_bulk_string(&mut buffer, &value);
        
        // 3. Execute with timing
        sw.start();
        let response_buffer = conn.send_request(&buffer).await?;
        sw.stop();
        
        // 4. Parse and validate
        let (_, response) = parse_response(&response_buffer)?;
        expect_ok(&response)?;
        
        // 5. Record metrics
        stats::record_latency(sw.elapsed_micros());
        stats::incr_requests_processed(1);
        stats::update_progress(1);
    }
    
    Ok(())
}
```

---

### 6. RESP Protocol Communication Workflow

#### Request Building

```mermaid
flowchart LR
    Command[Command Array] --> Builder[RespBuilderV2]
    Builder --> AddArray[add_array_len]
    AddArray --> AddCmd[add_bulk_string: CMD]
    AddCmd --> AddArg1[add_bulk_string: arg1]
    AddArg1 --> AddArgN[add_bulk_string: argN]
    AddArgN --> Buffer[BytesMut Buffer]
    Buffer --> Network[Send to Network]
```

**Example Construction:**

Command: `SET mykey myvalue`

```
add_array_len(3)     -> *3\r\n
add_bulk_string(SET) -> $3\r\nSET\r\n
add_bulk_string(key) -> $5\r\nmykey\r\n
add_bulk_string(val) -> $7\r\nmyvalue\r\n

Final: *3\r\n$3\r\nSET\r\n$5\r\nmykey\r\n$7\r\nmyvalue\r\n
```

#### Response Parsing

```mermaid
flowchart TB
    Network[Read from Network] --> Buffer[Accumulate in BytesMut]
    Buffer --> Parser[RespResponseParserV2::parse]
    
    Parser --> CheckType{First Byte}
    
    CheckType -->|+| ParseStatus[Parse Simple String]
    CheckType -->|-| ParseError[Parse Error]
    CheckType -->|:| ParseInteger[Parse Integer]
    CheckType -->|$| ParseBulk[Parse Bulk String]
    CheckType -->|*| ParseArray[Parse Array]
    
    ParseStatus --> CheckCRLF{Found \r\n?}
    ParseError --> CheckCRLF
    ParseInteger --> CheckCRLF
    
    ParseBulk --> ReadLen[Read Length]
    ReadLen --> CheckData{Have N+2 bytes?}
    CheckData -->|No| NeedMore[Return NeedMoreData]
    CheckData -->|Yes| ExtractData[Extract Data]
    
    ParseArray --> ReadCount[Read Array Count]
    ReadCount --> ParseElements[Parse Each Element]
    ParseElements --> ParseElements
    
    CheckCRLF -->|No| NeedMore
    CheckCRLF -->|Yes| ReturnObj[Return ValkeyObject]
    ExtractData --> ReturnObj
    ParseElements --> ReturnObj
    
    ReturnObj --> Caller[Return to Caller]
    NeedMore --> ReadMore[Read More from Network]
    ReadMore --> Buffer
```

---

### 7. Cluster Request Routing Workflow

```mermaid
sequenceDiagram
    participant Test
    participant Cluster
    participant SlotCalc
    participant ConnPool
    participant Node1
    participant Node2
    
    Test->>Cluster: send_request(buffer)
    Cluster->>SlotCalc: slot_from_buffer(buffer)
    SlotCalc->>SlotCalc: Extract key from RESP
    SlotCalc->>SlotCalc: calculate_slot(key)
    SlotCalc-->>Cluster: slot=1234
    
    Cluster->>ConnPool: get_or_create_connection(node1_addr)
    ConnPool-->>Cluster: ValkeyClient
    
    Cluster->>Node1: send_request(buffer)
    
    alt Success
        Node1-->>Cluster: Response
        Cluster-->>Test: Response
    else MOVED Error
        Node1-->>Cluster: -MOVED 1234 node2:7001\r\n
        Cluster->>Cluster: parse_moved(error)
        Cluster->>ConnPool: get_or_create_connection(node2_addr)
        ConnPool-->>Cluster: ValkeyClient (new)
        Cluster->>Node2: send_request(buffer)
        Node2-->>Cluster: Response
        Cluster-->>Test: Response
    end
```

**Slot Calculation Details:**

```
Key: "user:123:profile"
1. Check for hashtag: None found
2. Use full key: "user:123:profile"
3. CRC16(key) = X
4. Slot = X % 16384

Key: "user:{123}:profile"
1. Check for hashtag: Found "{123}"
2. Extract: "123"
3. CRC16("123") = Y
4. Slot = Y % 16384
```

---

### 8. Statistics Collection Workflow

```mermaid
flowchart TB
    subgraph "Task Execution"
        Task1[Task 1] --> Record1[record_latency]
        Task1 --> Incr1[incr_requests_processed]
        Task1 --> Update1[update_progress]
        
        Task2[Task 2] --> Record2[record_latency]
        Task2 --> Incr2[incr_requests_processed]
        Task2 --> Update2[update_progress]
    end
    
    subgraph "Global State"
        Record1 --> Histogram[HDR Histogram]
        Record2 --> Histogram
        
        Incr1 --> Counter1[REQUESTS_PROCESSED]
        Incr2 --> Counter1
        
        Update1 --> Progress[Progress Bar]
        Update2 --> Progress
    end
    
    subgraph "Finalization"
        AllDone[All Tasks Complete] --> Collect[Stats::collect]
        Collect --> ReadHist[Read Histogram]
        Collect --> ReadCounters[Read Counters]
        Collect --> CalcRPS[Calculate RPS]
        
        ReadHist --> Percentiles[Extract Percentiles]
        ReadCounters --> TotalReqs[Total Requests]
        CalcRPS --> RPS[Requests/Second]
        
        Percentiles --> StatsStruct[Stats Structure]
        TotalReqs --> StatsStruct
        RPS --> StatsStruct
        
        StatsStruct --> Output{Output Format}
        Output -->|JSON| JSONOut[JSON Serialization]
        Output -->|Human| FormatOut[Format & Display]
    end
```

**Lock-Free Design:**
- Atomic counters for request tracking
- Single mutex for histogram (rare contention)
- Progress bar updates batched
- No locks in hot path (request execution)

---

### 9. Pipeline Workflow

```mermaid
sequenceDiagram
    participant Test
    participant Client
    participant Network
    participant Server
    
    Note over Test: Pipeline = 3
    
    Test->>Test: Build request 1
    Test->>Test: Build request 2
    Test->>Test: Build request 3
    
    Test->>Client: send_request(req1)
    Client->>Network: write_all(req1)
    
    Test->>Client: send_request(req2)
    Client->>Network: write_all(req2)
    
    Test->>Client: send_request(req3)
    Client->>Network: write_all(req3)
    
    Server->>Network: Process & respond
    Server->>Network: Process & respond
    Server->>Network: Process & respond
    
    Network-->>Client: response1
    Client-->>Test: response1
    
    Network-->>Client: response2
    Client-->>Test: response2
    
    Network-->>Client: response3
    Client-->>Test: response3
```

**Implementation Note:** Current implementation sends one request at a time. True pipelining (batching multiple requests before reading responses) would require modifications to the Connection trait.

---

### 10. Error Handling Workflow

```mermaid
flowchart TB
    Operation[Execute Operation] --> Result{Result}
    
    Result -->|Ok| Success[Continue]
    Result -->|Err| CheckError{Error Type}
    
    CheckError -->|I/O Error| LogIO[Log I/O Error]
    CheckError -->|Parse Error| HandleParse{Parse Error Type}
    CheckError -->|Protocol Error| LogProtocol[Log Protocol Error]
    CheckError -->|Unexpected Response| LogUnexpected[Log Unexpected]
    
    HandleParse -->|NeedMoreData| ReadMore[Read More Bytes]
    HandleParse -->|Protocol Error| LogProtocol
    HandleParse -->|Buffer Too Big| FailFast[Fail Fast]
    
    ReadMore --> Operation
    
    LogIO --> Propagate[Propagate Error]
    LogProtocol --> Propagate
    LogUnexpected --> Propagate
    FailFast --> Propagate
    
    Propagate --> TaskFail[Task Fails]
    TaskFail --> ThreadCleanup[Thread Cleanup]
    ThreadCleanup --> StatsRecord[Record Partial Stats]
```

**Error Propagation:**
1. Low-level errors (I/O, parse) -> CommonError
2. Test validation errors -> BenchmarkError
3. Both propagate up via `?` operator
4. Thread catches and logs
5. Other threads continue execution

---

### 11. Graceful Shutdown Workflow

```mermaid
sequenceDiagram
    participant User
    participant CtrlC
    participant Main
    participant Threads
    participant Tasks
    
    User->>CtrlC: Press Ctrl+C
    CtrlC->>Main: Signal received
    
    Note over Main: Current implementation:<br/>Immediate exit via<br/>std::process::exit(0)
    
    Main->>Main: exit(0)
    
    Note over Threads: Alternative graceful approach<br/>(not implemented):
    
    Main->>Threads: Send shutdown signal
    Threads->>Tasks: Stop accepting new requests
    Tasks->>Tasks: Complete in-flight requests
    Tasks-->>Threads: Task done
    Threads-->>Main: Thread done
    Main->>Main: Display partial stats
```

**Current Behavior:** Immediate exit on Ctrl+C via `std::process::exit(0)`

**Potential Enhancement:** Could implement graceful shutdown with:
- Shared atomic flag
- Tasks check flag periodically
- Complete in-flight requests
- Report partial statistics

---

### 12. Preset Loading Workflow

```mermaid
flowchart TB
    Start[User invokes<br/>sb --preset name] --> LoadINI[Load ~/.sb.ini]
    LoadINI --> ParseINI[Parse INI file]
    ParseINI --> FindSection{Section [name]<br/>exists?}
    
    FindSection -->|No| Error[Error: Preset not found]
    FindSection -->|Yes| ExtractArgs[Extract argument string]
    
    ExtractArgs --> ParseArgs[Parse as CLI args]
    ParseArgs --> CreateOptions[Create Options struct]
    CreateOptions --> MergeCLI[Merge with CLI overrides]
    MergeCLI --> Finalize[Finalize options]
    Finalize --> Execute[Execute test]
    
    Error --> Exit[Exit with error]
```

**INI File Structure:**
```ini
[preset-name]
--option1 value1
--option2 value2
-shortopt value3
```

**Command-Line Override:**
```bash
sb --preset mypreset --threads 16
# Preset values + threads=16 override
```

---

### 13. Vector DB Ingestion Workflow

```mermaid
sequenceDiagram
    participant Test
    participant Utils
    participant Builder
    participant Client
    participant Server
    
    Note over Test: vecdb_ingest test
    
    Test->>Test: Get index name & prefix
    
    loop For each request
        Test->>Utils: generate_key()
        Utils-->>Test: key
        
        Test->>Utils: generate_vector(dim)
        Utils-->>Test: hex_string
        
        Test->>Builder: Build FT.ADD command
        Note over Builder: FT.ADD index key<br/>BLOB my_field \xHEX
        Builder-->>Test: request_buffer
        
        Test->>Test: Add to batch
    end
    
    Test->>Client: send_vecdb_ingest_request(batch)
    
    loop For each request in batch
        Client->>Server: Send request
        Server-->>Client: Response
    end
    
    Client-->>Test: responses[]
    
    Test->>Test: Validate all responses
```

**Special Features:**
- Batches multiple FT.ADD commands
- Generates random float32 vectors
- Hex-encodes vectors with `\x` prefix
- Uses special connection method for batch sending

---

## Common Patterns

### Pattern 1: Request-Response Cycle

```rust
// 1. Build request
let mut buffer = BytesMut::new();
builder.add_array_len(&mut buffer, args.len() + 1);
builder.add_bulk_string(&mut buffer, b"COMMAND");
for arg in args {
    builder.add_bulk_string(&mut buffer, arg);
}

// 2. Send with timing
stopwatch.start();
let response = connection.send_request(&buffer).await?;
stopwatch.stop();

// 3. Parse and validate
let (_, obj) = parse_response(&response)?;
validate_response(&obj)?;

// 4. Record stats
stats::record_latency(stopwatch.elapsed_micros());
stats::incr_requests_processed(1);
```

### Pattern 2: Connection Lazy Initialization

```rust
// Cluster maintains connection pool
async fn get_or_create_connection(&mut self, host: &str, port: u16) {
    let key = format!("{}:{}", host, port);
    
    if !self.connections.contains_key(&key) {
        let conn = ValkeyClient::connect(
            host.to_string(),
            port,
            self.use_tls
        ).await?;
        self.connections.insert(key.clone(), conn);
    }
    
    self.connections.get_mut(&key)
}
```

### Pattern 3: Progress Tracking

```rust
// Setup (once)
stats::finalise_progress_setup(total_requests as u64);

// During execution (each task)
stats::update_progress(1);

// Cleanup (once)
stats::finish_progress();
```
