# `sabledb-benchmark`

A modern, drop in replacement to Valkey's benchmark tool.


```bash
Usage: sabledb-benchmark [OPTIONS]

Options:
      --help                         Print this help message and exit
  -c, --connections <CONNECTIONS>    Total number of connections [default: 512]
      --threads <THREADS>            Number of threads to use. Each thread will run "connections / threads" connections [default: 1]
  -h, --host <HOST>                  Host address [default: 127.0.0.1]
  -p, --port <PORT>                  Host port [default: 6379]
  -t, --test <TEST>                  test suits to run. Possible values are:
                                     "set", "get", "lpush", "lpop", "incr", "rpop", "rpush", "ping", "hset", "setget".
                                     Note that when the test is "setget", you can control the ratio by passing: "--setget-ratio" [default: set]
  -d, --data-size <DATA_SIZE>        Payload data size [default: 256]
  -k, --key-size <KEY_SIZE>          Key size, in bytes. If not provided, the key size is calculated based on the requested key range.
                                     For example, if no "key_size" is provided and the "key_range" is 100,000, the key size will be 6
  -r, --key-range <KEY_RANGE>        Number of unique keys in the benchmark [default: 1000000]
  -n, --num-requests <NUM_REQUESTS>  Total number of requests [default: 1000000]
  -l, --log-level <LOG_LEVEL>        Log level
      --tls                          Use TLS handshake with SableDB / Valkey
      --ssl                          Same as "--tls"
  -P, --pipeline <PIPELINE>          Pipeline [default: 1]
      --setget-ratio <SETGET_RATIO>  The ratio between SET:GET when test is "SETGET".
                                     For example, passing "1:4" means: execute 1 SET for every 4 GET calls [default: 1:4]
  -z, --randomize                    Keys are generated using sequential manner, i.e. from "0" until "key-range" in an incremental step of "1".
                                     Passing "-z" or "--randomize" will generate random keys by generating random number from "0" -> "key-range".
  -s, --preset <PRESET>              Use preset command line. If set, sabledb-benchmark will search for the preset name
                                     in the configuration file $HOME/.sabledb-benchmark with that exact name and use the command line
                                     set there.
```

## Preset configurations

`sabledb-benchmark` supports "preset" tests. With this feature, a user can store multiple test execution command lines
inside a configuration file and re-use it later. With this feature you can avoid mistakes of missing a command line
argument...

An example for using the preset configuration:

* Create the configuration file `$HOME/.sabledb-benchmark`
* Place the below content into the file and save it:

```
[fill-database]
--threads 10 -c 512 --pipeline 5 -d 64 -n 5000000 -r 5000000 -t set

[setget-seq]
--threads 4 -c 512 -d 64 -n 5000000 -r 5000000 -t setget

[setget-random]
--threads 4 -c 512 -d 64 -n 5000000 -r 5000000 -t setget -z
```

* You can now use `sabledb-benchmark` using the following commands:

to fill the database:

```bash
sabledb-benchmark --preset fill-database
```

Run a readers/writers load using sequential keys:

```bash
sabledb-benchmark --preset setget-seq
```

Run a readers/writers load using random keys:

```bash
sabledb-benchmark --preset setget-random
```

![sabledb-benchmark progress demo](/images/sabledb-benchmark.gif)

# Building from sources

```bash
git clone https://github.com/sabledb-io/benchmark.git
cd benchmark
cargo build --release
```

Use it:

```bash
target/release/sabledb-benchmark --help
```

This project is part of [`SableDB`][1]

[1]: https://github.com/sabledb-io/sabledb


