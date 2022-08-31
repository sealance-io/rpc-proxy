# rpc-proxy

A reverse proxy for `web3` JSON RPC for both 'http' and 'websocket' transport types featuring:

- rate limiting
- method filtering
- stats

## Getting Started

### Prerequisites

At least Go 1.12. Installation documentation here: https://golang.org/doc/install

### How to Use

By default, `rpc-proxy` will run on port `8545` and redirect requests to `http://localhost:8040` and to `ws://localhost:8041`. These values
can be changed with the `port`, `url` and `wsurl` flags, along with other options:

```sh
> rpc-proxy help
NAME:
   rpc-proxy - A proxy for web3 JSONRPC

USAGE:
   rpc-proxy [global options] command [command options] [arguments...]

VERSION:
   0.0.60

COMMANDS:
     help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --config value, -c value    path to toml config file
   --port value, -p value      port to serve (default: "8545")
   --url value, -u value       redirect url (default: "http://127.0.0.1:8040")
   --wsurl value, -w value     redirect websocket url (default: "ws://127.0.0.1:8041")
   --allow value, -a value     comma separated list of allowed paths
   --rpm value                 limit for number of requests per minute from single IP (default: 1000)
   --nolimit value, -n value   list of ips allowed unlimited requests(separated by commas)
   --blocklimit value -b value block range query limit (default: 0 - none)
   --help, -h                  show help
   --version, -v               print the version
```

## Docker

Build Docker image:

```sh
make docker
```

Run it:

```sh
make run
```
