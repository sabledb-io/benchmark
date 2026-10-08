# `sb`

A modern, drop in replacement to Valkey's benchmark tool.


```bash
Usage: sb [OPTIONS]

Options:
      --help                         Print this help message and exit
  -c, --connections <CONNECTIONS>    Total number of connections [default: 512]
      --threads <THREADS>            Number of threads to use. Each thread will run "connections / threads" connections [default: 1]
  -h, --host <HOST>                  Host address [default: 127.0.0.1]
  -p, --port <PORT>                  Host port [default: 6379]
  -t, --test <TEST>                  test suits to run. Possible values are:
                                     "set", "get", "lpush", "lpop", "incr", "rpop", "rpush", "ping", "hset", "setget", "vecdb_ingest" and "ft.search".
                                     Note that when the test is "setget", you can control the ratio by passing: "--setget-ratio" [default: set]
  -d, --data-size <DATA_SIZE>        Payload data size [default: 256]
      --dataset <DATASET>            Use values from a pre-prepared dataset instead of random payloads. Each line in the file is one value,
                                     and a random line is picked for every command. Pass a file path, or a dataset name that is searched in
                                     "--dataset-dir" (for example: "taxi-trips" matches "taxi-trips.json.gz"). Gzip files are supported.
                                     When set, "--data-size" is ignored. Used by: "set", "setget", "lpush", "rpush" and "hset".
      --dataset-dir <DATASET_DIR>    Directory to search for "--dataset" names. If not set, use the "SB_DATASET_DIR" environment variable,
                                     or "./dataset" if it exists, or the current directory.
      --list-presets                 Print the presets found in "$HOME/.sb.ini" and exit.
      --list-datasets                Print value size statistics for every dataset in "--dataset-dir" and exit.
  -k, --key-size <KEY_SIZE>          Key size, in bytes. If not provided, the key size is calculated based on the requested key range.
                                     For example, if no "key_size" is provided and the "key_range" is 100,000, the key size will be 6
      --dim <DIM>                    When running vector DB ingestion ("-t vecdb_ingest") test, pass here the vector dimension size. [default: 128]
      --knn <KNN>                    KNN parameter to pass to the `FT.SEARCH` command. [default: 10]
      --vecdb-index <VECDB_INDEX>    When testing "vecdb_ingest", use this to pass the index name + the prefix as a comma separated strings [default: my_index,my_prefix]
      --vec-seed <VEC_SEED>          When loading vectors into the database, we use a global counter to generate the vector values. By default this
                                     seed is set to `0`. Use this to change it. With this, a user may generate unique vectors per execution. Default value: 0 [default: 0]
  -r, --key-range <KEY_RANGE>        Number of unique keys in the benchmark [default: 1000000]
      --limit-rps <LIMIT_RPS>        Upper limit on the total requests per second, shared by all connections.
                                     If not set, requests are sent as fast as possible.
      --touch-keys <TOUCH_KEYS>      Read commands (e.g. "get") touch only this percentage of the key space (1-100).
                                     For example, if the key range is 1,000,000 and the value is 30, only the first 300,000 keys are read.
                                     Write commands are not affected.
  -n, --num-requests <NUM_REQUESTS>  Total number of requests [default: 1000000]
  -l, --log-level <LOG_LEVEL>        Log level [default: error]
      --tls                          Use TLS handshake with SableDB / Valkey
      --ssl                          Same as "--tls"
  -P, --pipeline <PIPELINE>          Pipeline [default: 1]
      --setget-ratio <SETGET_RATIO>  The ratio between SET:GET when test is "SETGET".
                                     For example, passing "1:4" means: execute 1 SET for every 4 GET calls [default: 1:4]
  -z, --randomize                    Keys are generated using sequential manner, i.e. from "0" until "key-range" in an incremental step of "1".
                                     Passing "-z" or "--randomize" will generate random keys by generating random number from "0" -> "key-range".
  -s, --preset <PRESET>              Use preset command line. If set, "sb" will search for the preset name
                                     in the configuration file "$HOME/.sb.ini" with that exact name and use the command line
                                     set there.
      --cluster                      Use cluster enabled client.
      --json                         If set, the benchmark will dump a JSON report to stdout.
```

## Using a dataset for values

Use `--dataset` to send real values instead of random payloads. Each line in the file is one value,
and `sb` picks a random line for every command. Gzip files are supported.

```bash
sb -t set --dataset taxi-trips        # matches taxi-trips, taxi-trips.gz, taxi-trips.json.gz, ...
sb -t set --dataset /path/to/file.json.gz
sb --list-datasets                    # print value size stats (avg, p50, p90, p99, ...) and exit
```

Datasets are searched in `--dataset-dir`, then `$SB_DATASET_DIR`, then `./dataset` (if it exists), then the
current directory. This repository includes these datasets in `dataset/`:

| Name | Values | Avg | P50 | P99 |
|---|---|---|---|---|
| `github-events-50k` | 3,622 | 46.2KB | 45.6KB | 52.2KB |
| `github-events` | 10,000 | 2.0KB | 1.2KB | 16.9KB |
| `reddit-comments` | 10,000 | 530B | 440B | 1.7KB |
| `taxi-trips` | 10,000 | 456B | 456B | 461B |

When `--dataset` is set, `--data-size` is ignored. The dataset is used by `set`, `setget`, `lpush`, `rpush` and `hset`.

## Preset configurations

`sb` supports "preset" tests. With this feature, a user can store multiple test execution command lines
inside a configuration file and re-use it later. With this feature you can avoid mistakes of missing a command line
argument...

An example for using the preset configuration:

* Create the configuration file `$HOME/.sb.ini`
* Place the below content into the file and save it. Each section is a preset name, and the `command` key holds the command line:

```
[fill-database]
command = --threads 10 -c 512 --pipeline 5 -d 64 -n 5000000 -r 5000000 -t set

[setget-seq]
command = --threads 4 -c 512 -d 64 -n 5000000 -r 5000000 -t setget

[setget-random]
command = --threads 4 -c 512 -d 64 -n 5000000 -r 5000000 -t setget -z

[get-hot-keys]
command = --threads 4 -c 512 -n 5000000 -r 5000000 -t get --touch-keys 10 --limit-rps 50000
```

* Run `sb --list-presets` to see the available presets and their commands.
* You can now use `sb` using the following commands:

to fill the database:

```bash
sb --preset fill-database
```

Run a readers/writers load using sequential keys:

```bash
sb --preset setget-seq
```

Run a readers/writers load using random keys:

```bash
sb --preset setget-random
```

![sb progress demo](/images/sb.gif)

# Building from sources

```bash
git clone https://github.com/sabledb-io/benchmark.git
cd benchmark
cargo build --release
```

Use it:

```bash
target/release/sb --help
```

This project is part of [`SableDB`][1]

[1]: https://github.com/sabledb-io/sabledb


