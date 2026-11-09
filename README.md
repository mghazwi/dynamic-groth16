# Dynamic Groth16

A standalone Rust library for dynamic/partial Groth16 proving with arkworks 0.5. This will eventually be integrated into [ZeroKit's](https://github.com/vacp2p/zerokit). However, It is still useful for other use-cases beyond RLN, and so this crate does not depend on
ZeroKit, RLN, Circom tools, or any particular witness calculator at runtime.

- **V1** `Groth16DynamicV1` caches the linear contributions of fixed assignment values to the proof. Finishing
  still computes the ordinary QAP witness map and H-query contribution.
- **V2** `Groth16DynamicV2` also preprocesses the nonlinear contribution to proof C. Setup
  supports Circom/snarkjs-compatible and arkworks Libsnark H queries.

## Using the API

Given a compatible key `pk`, its unmodified constraint `matrices`, and an
assignment with the constant-one entry omitted:

```rust,ignore
use dynamic_groth16::{Groth16DynamicV1, Groth16DynamicV2, PartialAssignment, CircomReduction};

// Values are public entries excluding one, then private entries.
// Some(value) means fixed; None means it will be supplied when finishing.
let partial_assignment = PartialAssignment::new(values);

// V1: the QAP reduction must match the key.
let partial_v1 = Groth16DynamicV1::<Curve, CircomReduction>::preprocess(&pk, &partial_assignment)?;
let proof_v1 = Groth16DynamicV1::<Curve, CircomReduction>::finish_with_matrices(
    &pk, &partial_v1, r, s, &matrices, num_inputs, num_constraints, &full_assignment,
)?;

// V2: setup is reusable for the same key; preprocessing is reusable while
// the fixed assignment/witness values and dynamic mask remain unchanged.
let setup = Groth16DynamicV2::<Curve>::setup::<CircomReduction>(&pk)?;
let partial_v2 = Groth16DynamicV2::<Curve>::preprocess(&pk, &matrices, &setup, &partial_assignment)?;
let proof_v2 = Groth16DynamicV2::<Curve>::finish_with_randomness(
    &pk, &matrices, &setup, &full_assignment, r, s, &partial_v2,
)?;
```


## Test

```sh
cargo test
cargo test --no-default-features
```

The default `parallel` feature enables arkworks/Rayon parallelism. Disable
`default-features` to build without this parallel feature. The tests
compare v1 and v2 proofs with ordinary Groth16 proofs for both
Circom-compatible and Libsnark reduction paths using a small multiplication circuit.

### TODO
- V3 subgroup proving is not implemented yet.
