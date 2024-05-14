
# aya-tracepoint-echo-open

This is an experimentation with eBPF tracepoint, using smaller stack variable.
The intention is to understand the logic of copying data from kernel-space to user-space.
The original code is generated using Rust-Aya 0.1.0 and then modified to help   in experimentation.




## Prerequisites

1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Build Userspace

```bash
cargo build
```

## Run

```bash
RUST_LOG=info cargo xtask run
```
