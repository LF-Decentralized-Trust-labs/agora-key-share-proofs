# Key Share Proofs

This crate provides an implementation of Throback, an auditable hot-cold threshold backup system based on BLS signatures.

## Usage
Compile and run the benchmarks with `cargo run -r --example bench [t] [n] [samples]`, where `t` is the threshold number of parties (maximum the total number of parties `n`) required to produce a signature. The default setting is `3` out of `5`. Use `samples` to set the number of iterations to average over for the runtimes. This will write the benchmarks into a file called `benchmarks.txt`.

The paper contains benchmarks obtained with the following commands:
```
# small setting
cargo run -r --example bench 3 5 1000
# medium
cargo run -r --example bench 5 20 1000
# large
cargo run -r --example bench 67 100 1000
```

To run the tests:
```
# specify test name
cargo test --test [test name]

# all tests
cargo test
```

One can also compile the code (without running anything) with `cargo build`.

## License

Licensed under Apache License, Version 2.0, ([LICENSE](LICENSE) or http://www.apache.org/licenses/LICENSE-2.0)