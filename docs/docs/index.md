# `sb` - SableDB Benchmarking Tool

`sb` (short for: SableDB benchmark) is part of the tooling for [`SableDB`][1]. In order to be a "drop-in" replacement for
`valkey-benchmark` or `redis-benchmark`, `sb` uses the same switches.

## Features

- Visual progress bar + ETA
- A standalone tool, does not require to build `SableDB` or `Valkey`
- Support multi-threads + multi-connections
- Uses configuration file to persist executions
- Support for SET/GET load 
- Support SSL/TLS

```
Usage: sb [OPTIONS]

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
  -s, --preset <PRESET>              Use preset command line. If set, "sb" will search for the preset name
                                     in the configuration file "$HOME/.sb.ini" with that exact name and use the command line
                                     set there.
```


[1]: https://sabledb-io.github.io/sabledb/

