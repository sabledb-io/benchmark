# `sabldb-benchmark`

A modern, drop in replacement to Valkey's benchmark tool.


```bash
Usage: sabledb-benchmark [OPTIONS]

Options:
      --help                         Print this help message and exit
  -c, --connections <CONNECTIONS>    Total number of connections [default: 512]
      --threads <THREADS>            Number of threads to use. Each thread will run `connections / threads` connections [default: 1]
  -h, --host <HOST>                  Host address [default: 127.0.0.1]
  -p, --port <PORT>                  Host port [default: 6379]
  -t, --test <TEST>                  test suits to run. Possible values are:
                                     `set`, `get`, `lpush`, `lpop`, `incr`, `rpop`, `rpush`, `ping`, `hset`, `setget`.
                                     Note when the test is `setget`, you can control the ratio by passing: `--setget-ratio` [default: set]
  -d, --data-size <DATA_SIZE>        Payload data size [default: 256]
  -k, --key-size <KEY_SIZE>          Key size, in bytes. If not provided, the key size is calculated based on the requested key range
                                     For example, if no "key_size" is provided and the "key_range" is 100,000, the key size will be 6
  -r, --key-range <KEY_RANGE>        Number of unique keys in the benchmark [default: 1000000]
  -n, --num-requests <NUM_REQUESTS>  Total number of requests [default: 1000000]
  -l, --log-level <LOG_LEVEL>        Log level [Default: INFO]
      --tls                          use TLS [Default: false]
      --ssl                          Same as `--tls` [Default: false]
      --pipeline <PIPELINE>          Pipeline [default: 1]
      --setget-ratio <SETGET_RATIO>  The ratio between set:get when test is "setget"
                                     For example, passing "1:4" means: execute 1 set for every 4 get calls [default: 1:4]
  -z, --randomize                    By default, keys are generated using sequential manner, i.e. `0` -> `key-range` in an incremental
                                     step of `1`. Pass `-z` or `--randomize` so that keys are generated in a random manner from `0` -> `key-range` [Default: false]
```

![sabledb-benchmark progress demo](/images/sabledb-benchmark.gif)


This project is part of [`SableDB`][1]

[1]: https://github.com/sabledb-io/sabledb


