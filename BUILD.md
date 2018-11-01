# Building `Stegos` from source

## Requirements

* `Stegos` requires **Rust version 1.30.x or higher** to build.

    The recommended way to install Rust it to use [rustup](https://www.rustup.rs/).
    If you don't already have `rustup`, you can install it like this:

    ```bash
    $ curl https://sh.rustup.rs -sSf | sh
    ```

    Make sure that these binaries are in your `PATH`.
    After that, you should be able to build Stegos from the source.

* `libpbc` - we expect `libpbc` and GNU MP libs and headers installed in `/usr/local`. Binaries for Linux and MacOS can be grabbed at https://github.com/emotiq/emotiq-external-libs/releases.

    On MacOS libararies can also be installed using Homebrew:

    ```bash
    brew install pbc gmp
    ```

* to generate Rust code from protobuf specification we also need protobuf compiler to be installed.

    Under Debian/Ubuntu this can be installed with:

    ```bash
    apt-get update && apt-get install -y protobuf-compiler
    ```

    On macOS install it with Homebrew:

    ```bash
    brew install protobuf
    ```

## Building

Run `cargo build` to create the main executable:

```bash
# build in release mode
$ cargo build --release
```

This produces `stegos` executable in the `./target/release` subdirectory.
