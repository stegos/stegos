# Running test nodes locally

## Prerequisite

To generate node's configurations, Jinja2 CLI tool is needed.
It can be installed with:

```shell
pip install j2cli
```

## Prepare configurations

1. Remove previous configs

```shell
rm -rf testing/node*
```

1. Generate new configurations, keys, and genesis block for N nodes:

```shell
./create-testing-keys.sh N
```

1. Build the code with new Genesis block:

```shell
cargo build --release
```

## Start N nodes:

```shell
./start-cluster.sh N
```

Attach to the Leader node:

```shell
tmux a -t node01
```

## Stop all nodes:

```shell
./stop-cluster.sh N
```

## Reset database to initial conditions
```shell
./clear-database.sh
```
