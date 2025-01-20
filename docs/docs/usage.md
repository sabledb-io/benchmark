# Using `sb`


## General usage

A typical test will be:

- Populate the database
- Run the test

By default, `sb` does not require any parameters, it will:

- Attempt to connect to `SableDB` / `Valkey` / `Redis` listening on `127.0.0.1` using port `6379`
- Uses `1` thread
- Each thread will open `512` connections
- Data size is set to: `256` bytes
- Key size is set to `7` bytes
- It will generate `1M` unique keys (e.g. `0000001`, `0000002` .. `1000000`)
- The default test is `SET`


Obviously, these parameters can all be modified, see `sb --help` for for more details


## Presets

When executed, `sb` searches for a configuration file under your home directory. Under Linux, this will be: `$HOME/.sb.ini`.
This file can hold multiple execution configurations so you won't have to type them each time.

For example, consider the following use case:

- I would like to fill the database with `1M` unique records, each with payload of 256 bytes.
- Once the database is populated, I would like to run a load that tests for `SET`/`GET`, where for every `1` `SET` operation, the benchmark executes `4` `GET` calls.
- Use 512 connections spreaded across 10 threads

Now, one could write this manually (each time):

```bash
# fill the database
sb --threads 10 -t set -d 256 -c 512 -r 1000000

# run setget test
sb --threads 10 -t setget --setget-ratio "1:4" -d 256 -c 512 -n 10000000 -r 1000000 -z
```

As you can see, this is doable, however, its error prone, i.e. you can easily forget to type a parameter and report wrong results.
To solve this, we can instead, create a the file `~/.sb.ini` with the following content:

```ini
[filldb]
command="--threads 10 -t set -d 256 -c 512 -r 1000000"

[load]
command="--threads 10 -t setget --setget-ratio "1:4" -d 256 -c 512 -n 10000000 -r 1000000 -z"
```

And now, instead of typing the complete command each time, we can simply do this:

```bash
sb --preset filldb
sb --preset load
```
