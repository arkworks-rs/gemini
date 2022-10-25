Gemini: Elastic Arguments for R1CS.

This library provides essentially two arguments:
- [`snark::Proof`], for non-preprocessing SNARKs.
    It provides a non-interactive succinct argument of knowledge for R1CS
    without indexer, and where the verifier complexity is linear in the circuit size.
- [`psnark::Proof`] for preprocessing SNARKs.
    It provides a non-interactive succinct argument of knowledge for R1CS
    where the verifier complexity is logarithmic in the circuit size.

The library implements the Kate-Zaverucha-Goldberg protocol [[KZG](https://www.iacr.org/archive/asiacrypt2010/6477178/6477178.pdf)] 
for polynomial commitments.

### KZG Protocol Outline

1. Trusted setup and key generation
2. Commitment to a polynomial $f(x) \in \FF\[x\]$.
4. Evaluation of polynomial and proof generation
5. Verification of evaluation proof

The `kzg` and [`multikzg`] modules contain implementations of both time-efficient and space-efficient
versions of KZG polynomial commitments.

The choice of the pairing-friendly elliptic curve to be used is entirely up to the user.
For example, crate [`ark_bls12_381`] contains the implementation for curve [`Bls12_381`](ark_bls12_381::Bls12_381).

See the module documentation for `multikzg` below for an overview of protocol math.

# Building

This package can be compiled with `cargo build`. For now, this package can be built on rust stable.
Test package with `cargo test`.
Compile package documentation with `cargo rustdoc` and launch in default browser with `cargo rustdoc --open`.

Both arguments rely on some sub-protocols, implemented as separate modules in [`subprotocols`]
and free of use for other protocols.

# Building

This package can be compiled with `cargo build`, and requires rust nightly at least
until [`Iterator::advance_by`] hits stable. There's a bunch of feature flags that can be turned
on:

- `asm`, to turn on the assembly backend within [`ark-ff`](https://docs.rs/ark-ff/);
- `parallel`, to turn on multi-threading. This requires the additional dependency [`rayon`](https://docs.rs/rayon/latest/rayon/);
- `std`, to rely on the Rust Standard library;
- `print-trace`, to print additional information concerning the execution time of the sub-protocols. **This feature must be enabled if want to print the execution time of the examples.**

# Benchmarking

Micro-benchmarks aare available and can be fired with:

```bash
cargo bench
```

Execution of (preprocessing-)SNARK for arbitrary instance sizes can be done running
the examples with:

```bash
cargo run --example snark -- -i <INSTANCE_LOGSIZE>
```

# License

This package is licensed under MIT license.
