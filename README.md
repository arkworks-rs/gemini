<p align="center">
  <img src="doc/logo.svg" width=600px />
</p>

Gemini is elastic proof system system, FFT-free, blazingly fast and space-conscious.
However, this code is **not** meant for production use and has not been audited (yet).

To benchmark an instance of *logarithmic* size `$SIZE`, run the following:

```
cargo run --features asm,print-trace,parallel --example snark $SIZE
```
You monitor the memory used setting the environment variable `RUST_LOG=debug`.
We tested so far ranges `$SIZE` up to 35.

Space footprint for the prover can be tweaked playing with the following constants:
- `TENSOR_EXPANSION_LOG` (set to 16) which sets the space budget for expanding the tensor products;
- `MAX_MSM_BUFFER_LOG` (set to 20) the size of the buffers over which Gemini performs multi-scalar multiplication;
- `SPACE_TIME_THRESHOLD` (set to 22) the threshold for converting the space-prover into the time-prover.
It will run a separate thread measuring stack+heap consumption.
