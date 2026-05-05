# Codebase Information

## Project Overview

**Project Name:** sb (SableDB Benchmark)  
**Type:** Performance benchmarking tool  
**Primary Language:** Rust  
**Purpose:** A modern, drop-in replacement for Valkey/Redis benchmark tool

## Repository Structure

```
benchmark/
├── .agents/           # AI agent documentation (auto-generated)
├── .codelite/        # CodeLite IDE configuration
├── .git/             # Git repository data
├── common/           # Shared library (sbcommonlib)
├── docs/             # Documentation (MkDocs)
├── images/           # Project images and assets
├── sabledb-benchmark/ # Main benchmark application (sb)
├── target/           # Rust build artifacts
├── Cargo.toml        # Workspace configuration
├── Cargo.lock        # Dependency lock file
├── README.md         # Project README
├── LICENSE           # License file
└── TODO.md           # Future enhancements
```

## Technology Stack

### Programming Language
- **Rust** (Edition 2021)

### Build System
- **Cargo** (Rust workspace with 2 members)

### Key Dependencies

#### Async Runtime & Networking
- `tokio` - Async runtime with full features
- `tokio-rustls` - TLS support for async connections
- `futures` - Async combinators

#### CLI & Configuration
- `clap` - Command-line argument parsing (with derive features)
- `rust-ini` - INI file parsing for presets

#### Data Processing
- `bytes` - Efficient byte buffer management
- `rand` - Random number generation
- `serde` / `serde_json` - Serialization

#### Performance & Statistics
- `hdrhistogram` - High dynamic range histogram for latency tracking
- `indicatif` - Progress bars and status indicators

#### Error Handling
- `thiserror` - Ergonomic error types

#### Utilities
- `colored` - Terminal color output
- `num-format` - Number formatting
- `hex` - Hexadecimal encoding
- `wildmatch` - Pattern matching
- `async-trait` - Async traits
- `crc16` - CRC16 checksum for cluster slot calculation

## Workspace Members

### 1. common (sbcommonlib)
**Location:** `common/`  
**Binary Name:** sbcommonlib  
**Purpose:** Shared library providing core protocol and utility functionality

**Modules:**
- `errors` - Error types and handling
- `file_utils` - File operations
- `pattern_matcher` - Pattern matching utilities
- `request_parser` - RESP protocol request parsing
- `resp_builder_v2` - RESP protocol response building
- `resp_response_parser_v2` - RESP protocol response parsing
- `stopwatch` - Timing utilities
- `ticker` - Periodic tick functionality

### 2. sabledb-benchmark (sb)
**Location:** `sabledb-benchmark/`  
**Binary Name:** sb  
**Purpose:** Main benchmark application

**Modules:**
- `main` - Application entry point and thread orchestration
- `sb_options` - CLI options and configuration
- `valkey_client` - Client implementations (single node and cluster)
- `tests` - Benchmark test implementations
- `stats` - Statistics collection and reporting
- `bench_utils` - Utility functions for benchmarking
- `build` - Build script for platform-specific configuration

## Supported Test Types

The benchmark supports the following test operations:
- `set` - SET command benchmark
- `get` - GET command benchmark
- `setget` - Mixed SET/GET workload with configurable ratio
- `ping` - PING command benchmark
- `incr` - INCR command benchmark
- `lpush` / `lpop` - List push/pop operations (left)
- `rpush` / `rpop` - List push/pop operations (right)
- `hset` - Hash SET operations
- `vecdb_ingest` - Vector database ingestion test

## Protocol Support

- **RESP (REdis Serialization Protocol) v2** - Full implementation for Valkey/Redis compatibility
- **TLS/SSL** - Optional encrypted connections
- **Cluster Mode** - Redis/Valkey cluster protocol with slot-based routing

## Build Configuration

### Release Profile
```toml
[profile.release]
lto = true              # Link-time optimization
codegen-units = 1       # Single codegen unit for better optimization
strip = "symbols"       # Strip symbols from binary
```

### Platform-Specific
- Windows: Links against pthread library via build script

## Key Features

1. **Multi-threaded Architecture** - Configurable thread count with connection pooling
2. **Async I/O** - Built on Tokio for efficient concurrent operations
3. **Pipelining Support** - Configurable pipeline depth
4. **TLS Support** - Secure connections with certificate verification bypass
5. **Cluster Support** - Automatic slot calculation and MOVED/ASK redirection handling
6. **Preset Configurations** - Store and reuse test configurations via INI files
7. **Progress Tracking** - Real-time progress bars and statistics
8. **Latency Histograms** - HDR histogram for accurate latency percentiles
9. **JSON Output** - Machine-readable output format

## Configuration Files

- `$HOME/.sb.ini` - Preset configuration file for storing reusable test scenarios

## Code Metrics

- **Primary Language:** Rust
- **Total Rust Files:** 16
- **Workspace Structure:** Multi-package workspace
- **Test Coverage:** Unit tests present in bench_utils module

## Documentation

- **README.md** - User-facing documentation with usage examples
- **TODO.md** - Planned features and enhancements
- **MkDocs** - Documentation site configuration present

## License

Project includes a LICENSE file (not examined in detail)

## Development Environment

- **IDE Support:** CodeLite configuration present
- **Version Control:** Git repository
- **Ignore Patterns:** Standard Rust .gitignore with target/, debug/ exclusions
