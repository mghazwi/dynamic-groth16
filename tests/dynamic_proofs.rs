use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_ff::{Field, One};
use ark_groth16::{prepare_verifying_key, Groth16};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};
use ark_std::{
    rand::{rngs::StdRng, SeedableRng},
    UniformRand,
};
use dynamic_groth16::{
    CircomReduction, DynamicSetup, Groth16DynamicV1, Groth16DynamicV2, PartialAssignment,
};

#[derive(Clone, Copy)]
struct MulCircuit<F: Field> {
    a: Option<F>,
    b: Option<F>,
}

impl<F: Field> ConstraintSynthesizer<F> for MulCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| {
            Ok(self.a.ok_or(SynthesisError::AssignmentMissing)?
                * self.b.ok_or(SynthesisError::AssignmentMissing)?)
        })?;
        cs.enforce_constraint(
            ark_relations::lc!() + a,
            ark_relations::lc!() + b,
            ark_relations::lc!() + c,
        )
    }
}

#[test]
fn test_dynamic_proof_with_circuit() {
    let mut rng = StdRng::seed_from_u64(123);
    let (pk, vk) =
        Groth16::<Bn254, CircomReduction>::setup(MulCircuit::<Fr> { a: None, b: None }, &mut rng)
            .unwrap();
    let (a, b) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
    let circuit = MulCircuit {
        a: Some(a),
        b: Some(b),
    };
    let cs = ConstraintSystem::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    cs.finalize();
    let matrices = cs.to_matrices().unwrap();
    let setup = DynamicSetup::from_circom_key(&pk).unwrap();
    // Fix a; b and the public result can change between completions.
    let assignment = PartialAssignment::new(vec![None, Some(a), None]);
    let partial =
        Groth16DynamicV2::<Bn254>::preprocess(&pk, &matrices, &setup, &assignment).unwrap();

    let v1 = Groth16DynamicV1::<Bn254, CircomReduction>::preprocess(&pk, &assignment).unwrap();
    let v2_setup = Groth16DynamicV2::<Bn254>::setup(&pk).unwrap();
    let v2 = Groth16DynamicV2::<Bn254>::preprocess(&pk, &matrices, &v2_setup, &assignment).unwrap();
    for b in [b, Fr::from(7u64), Fr::from(0u64)] {
        let circuit = MulCircuit {
            a: Some(a),
            b: Some(b),
        };
        let mut dynamic_rng = rng.clone();
        let mut full_rng = rng.clone();
        let mut v1_rng = rng.clone();
        let mut v2_rng = rng.clone();
        let dynamic =
            Groth16DynamicV2::<Bn254>::finish(&pk, circuit, &setup, &mut dynamic_rng, &partial)
                .unwrap();
        let full = Groth16::<Bn254, CircomReduction>::prove(&pk, circuit, &mut full_rng).unwrap();
        let p1 = Groth16DynamicV1::<Bn254, CircomReduction>::finish(&pk, circuit, &mut v1_rng, &v1)
            .unwrap();
        let p2 =
            Groth16DynamicV2::<Bn254>::finish(&pk, circuit, &v2_setup, &mut v2_rng, &v2).unwrap();
        assert_eq!(p1, full);
        assert_eq!(p2, full);
        assert_eq!(dynamic, full);
        assert!(Groth16::<Bn254>::verify_with_processed_vk(
            &prepare_verifying_key(&vk),
            &[a * b],
            &dynamic,
        )
        .unwrap());
    }
    let missing = MulCircuit {
        a: Some(a),
        b: None,
    };
    assert!(Groth16DynamicV2::<Bn254>::finish(&pk, missing, &setup, &mut rng, &partial).is_err());
    let changed = MulCircuit {
        a: Some(a + Fr::one()),
        b: Some(b),
    };
    assert!(Groth16DynamicV2::<Bn254>::finish(&pk, changed, &setup, &mut rng, &partial).is_err());
}

#[test]
fn test_dynamic_proof_with_matrices() {
    let mut rng = StdRng::seed_from_u64(42);
    let (pk, vk) =
        Groth16::<Bn254, CircomReduction>::setup(MulCircuit::<Fr> { a: None, b: None }, &mut rng)
            .unwrap();
    let pvk = prepare_verifying_key(&vk);
    let a = Fr::rand(&mut rng);
    let b = Fr::rand(&mut rng);
    let c = a * b;
    let circuit = MulCircuit {
        a: Some(a),
        b: Some(b),
    };
    let cs = ConstraintSystem::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    cs.finalize();
    assert!(cs.is_satisfied().unwrap());
    let matrices = cs.to_matrices().unwrap();
    let full_assignment = [Fr::one(), c, a, b];

    // Keep a fixed and leave b and the public output dynamic.
    let assignment = PartialAssignment::new(vec![None, Some(a), None]);
    let setup = DynamicSetup::from_circom_key(&pk).unwrap();
    let partial =
        Groth16DynamicV2::<Bn254>::preprocess(&pk, &matrices, &setup, &assignment).unwrap();

    // The same r and s allow comparison with the full and simple partial provers.
    let mut matrix_rng = rng.clone();
    let r = Fr::rand(&mut rng);
    let s = Fr::rand(&mut rng);
    let dynamic = Groth16DynamicV2::<Bn254>::finish_with_randomness(
        &pk,
        &matrices,
        &setup,
        &full_assignment,
        r,
        s,
        &partial,
    )
    .unwrap();
    let full = Groth16::<Bn254, CircomReduction>::create_proof_with_reduction_and_matrices(
        &pk,
        r,
        s,
        &matrices,
        cs.num_instance_variables(),
        cs.num_constraints(),
        &full_assignment,
    )
    .unwrap();
    let simple = Groth16DynamicV1::<Bn254, CircomReduction>::finish_with_matrices(
        &pk,
        partial.linear_partial(),
        r,
        s,
        &matrices,
        cs.num_instance_variables(),
        cs.num_constraints(),
        &full_assignment,
    )
    .unwrap();
    assert_eq!(dynamic, full);
    assert_eq!(dynamic, simple);
    let api_v1 = Groth16DynamicV1::<Bn254, CircomReduction>::finish_with_matrices(
        &pk,
        partial.linear_partial(),
        r,
        s,
        &matrices,
        cs.num_instance_variables(),
        cs.num_constraints(),
        &full_assignment,
    )
    .unwrap();
    let api_v2 = Groth16DynamicV2::<Bn254>::finish_with_matrices(
        &pk,
        &matrices,
        &setup,
        &full_assignment,
        &mut matrix_rng,
        &partial,
    )
    .unwrap();
    assert_eq!(api_v1, full);
    assert_eq!(api_v2, full);
    assert!(Groth16::<Bn254>::verify_with_processed_vk(&pvk, &[c], &dynamic).unwrap());
}

#[test]
fn all_masks_match_full_circom_proof() {
    let mut rng = StdRng::seed_from_u64(82741);
    let (pk, _) =
        Groth16::<Bn254, CircomReduction>::setup(MulCircuit::<Fr> { a: None, b: None }, &mut rng)
            .unwrap();
    let (a, b) = (Fr::from(3u64), Fr::from(7u64));
    let circuit = MulCircuit {
        a: Some(a),
        b: Some(b),
    };
    let cs = ConstraintSystem::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    cs.finalize();
    let matrices = cs.to_matrices().unwrap();
    let full = [Fr::one(), a * b, a, b];
    let setup = Groth16DynamicV2::<Bn254>::setup(&pk).unwrap();
    for mask in 0..8 {
        let partial = PartialAssignment::new(
            full[1..]
                .iter()
                .enumerate()
                .map(|(i, &value)| {
                    if (mask >> i) & 1 == 1 {
                        Some(value)
                    } else {
                        None
                    }
                })
                .collect(),
        );
        let v1 = Groth16DynamicV1::<Bn254, CircomReduction>::preprocess(&pk, &partial).unwrap();
        let v2 = Groth16DynamicV2::<Bn254>::preprocess(&pk, &matrices, &setup, &partial).unwrap();
        for (r, s) in [
            (Fr::from(0u64), Fr::from(0u64)),
            (Fr::from(5u64), Fr::from(7u64)),
        ] {
            let reference =
                Groth16::<Bn254, CircomReduction>::create_proof_with_reduction_and_matrices(
                    &pk,
                    r,
                    s,
                    &matrices,
                    cs.num_instance_variables(),
                    cs.num_constraints(),
                    &full,
                )
                .unwrap();
            let p1 = Groth16DynamicV1::<Bn254, CircomReduction>::finish_with_matrices(
                &pk,
                &v1,
                r,
                s,
                &matrices,
                cs.num_instance_variables(),
                cs.num_constraints(),
                &full,
            )
            .unwrap();
            let p2 = Groth16DynamicV2::<Bn254>::finish_with_randomness(
                &pk, &matrices, &setup, &full, r, s, &v2,
            )
            .unwrap();
            assert_eq!(p1, reference, "v1 mask {mask}");
            assert_eq!(p2, reference, "v2 mask {mask}");
        }
    }
}

// Exercise a larger set of constraint rows than the single-multiplication fixture.
#[derive(Clone, Copy)]
struct RepeatedMul(MulCircuit<Fr>);

impl ConstraintSynthesizer<Fr> for RepeatedMul {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        for _ in 0..80 {
            self.0.generate_constraints(cs.clone())?;
        }
        Ok(())
    }
}

#[test]
fn larger_circuit_proof_matches_full_prover() {
    let mut rng = StdRng::seed_from_u64(87321);
    let empty = RepeatedMul(MulCircuit { a: None, b: None });
    let (pk, vk) = Groth16::<Bn254, CircomReduction>::setup(empty, &mut rng).unwrap();
    let circuit = RepeatedMul(MulCircuit {
        a: Some(Fr::from(3u64)),
        b: Some(Fr::from(7u64)),
    });
    let cs = ConstraintSystem::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    cs.finalize();
    let matrices = cs.to_matrices().unwrap();
    let setup = DynamicSetup::from_circom_key(&pk).unwrap();
    let mut full_assignment = cs.borrow().unwrap().instance_assignment.clone();
    full_assignment.extend_from_slice(&cs.borrow().unwrap().witness_assignment);
    // Exercise both all-dynamic and all-fixed assignments with identical
    // randomizers in the dynamic and ordinary provers.
    for dynamic in [true, false] {
        let assignment = PartialAssignment::new(
            full_assignment[1..]
                .iter()
                .map(|&value| if dynamic { None } else { Some(value) })
                .collect(),
        );
        let partial =
            Groth16DynamicV2::<Bn254>::preprocess(&pk, &matrices, &setup, &assignment).unwrap();
        let (r, s) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
        let actual = Groth16DynamicV2::<Bn254>::finish_with_randomness(
            &pk,
            &matrices,
            &setup,
            &full_assignment,
            r,
            s,
            &partial,
        )
        .unwrap();
        let expected = Groth16::<Bn254, CircomReduction>::create_proof_with_reduction_and_matrices(
            &pk,
            r,
            s,
            &matrices,
            cs.num_instance_variables(),
            cs.num_constraints(),
            &full_assignment,
        )
        .unwrap();
        assert_eq!(actual, expected);
        assert!(Groth16::<Bn254>::verify_with_processed_vk(
            &prepare_verifying_key(&vk),
            &full_assignment[1..cs.num_instance_variables()],
            &actual
        )
        .unwrap());
    }
}
