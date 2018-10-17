# Running test nodes locally

* build the code:

```shell
cargo build
```

* run nodes sequentially (NN = 01, 02, 03):

```shell
cargo run -- -c testing/nodeNN/stegos.toml
```

`Node01` is simply listening on configured port (10055) and doesn't make any attempts to connect to any peers.

`Node02` on start will start listening on port (10056) and connects to `Node01`

`Node03` listens on port 10057 and connects to `Node01` and `Node02`

Anything typed on stdin is broadcasted to all connected nodes.
Typing `dial <multiaddr>` will connect to other node, listening on provided Multiaddr.

Multiaddr has format: `/ip4/<IP>/tcp/<port>`

DNS current is not supported.
