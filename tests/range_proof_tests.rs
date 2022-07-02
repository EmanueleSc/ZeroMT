#[cfg(test)]
mod range_proof_tests {
    use ark_bn254::G1Affine as G1Point;
    use ark_serialize::CanonicalSerialize;
    use core::panic;
    use merlin::Transcript;
    use rand::Rng;
    use serial_test::serial;
    use std::io::Error;
    use zeromt::{
        ExecTimeBenchmark, InnerProof, InnerProofArguments, InnerProver, InnerVerifier, RangeProof,
        RangeProver, RangeVerifier, Utils,
    };

    #[test]
    fn verify_range_proof_test() {
        let mut prover_trans: Transcript = Transcript::new(b"RangeProofTest");
        let mut verifier_trans: Transcript = Transcript::new(b"RangeProofTest");

        let mut rng = ark_std::rand::thread_rng();
        let g: G1Point = Utils::get_curve_generator();
        let h: G1Point = Utils::get_n_generators_berkeley(1, &mut rng)[0];

        let (total_balance, amounts, balance_remaining) = Utils::get_mock_balances(4, &mut rng);

        let (proof, inner_arguments): (RangeProof, InnerProofArguments) =
            RangeProver::new(&mut prover_trans, &g, &h, balance_remaining, &amounts)
                .generate_proof(&mut rng);

        let result =
            RangeVerifier::new(&mut verifier_trans, &g, &h, amounts.len()).verify_proof(&proof);

        if result.is_ok() {
            assert!(true);
        } else {
            panic!("Verifier fails");
        }
    }

    #[test]
    fn verify_range_proof_with_inner_test() {
        let mut prover_trans: Transcript = Transcript::new(b"RangeProofTest");
        let mut verifier_trans: Transcript = Transcript::new(b"RangeProofTest");

        let mut rng = ark_std::rand::thread_rng();
        let g: G1Point = Utils::get_curve_generator();
        let h: G1Point = Utils::get_n_generators_berkeley(1, &mut rng)[0];

        let (total_balance, amounts, balance_remaining) = Utils::get_mock_balances(4, &mut rng);

        let (range_proof, inner_arguments): (RangeProof, InnerProofArguments) =
            RangeProver::new(&mut prover_trans, &g, &h, balance_remaining, &amounts)
                .generate_proof(&mut rng);

        let range_proof_result = RangeVerifier::new(&mut verifier_trans, &g, &h, amounts.len())
            .verify_proof(&range_proof);

        let mut verifier_multiscalar_trans: Transcript = verifier_trans.clone();

        let u: G1Point = Utils::get_n_generators_berkeley(1, &mut rng)[0];

        let inner_proof: InnerProof = InnerProver::new(
            &mut prover_trans,
            inner_arguments.get_g_vec(),
            inner_arguments.get_h_first_vec(),
            inner_arguments.get_phu(),
            inner_arguments.get_t_hat(),
            inner_arguments.get_l(),
            inner_arguments.get_r(),
            &u,
        )
        .generate_proof();

        let inner_result = InnerVerifier::new(
            &mut verifier_trans,
            inner_arguments.get_g_vec(),
            inner_arguments.get_h_first_vec(),
            inner_arguments.get_phu(),
            inner_arguments.get_t_hat(),
            &u,
        )
        .verify_proof(&inner_proof);

        let inner_multiscalar_result = InnerVerifier::new(
            &mut verifier_multiscalar_trans,
            inner_arguments.get_g_vec(),
            inner_arguments.get_h_first_vec(),
            inner_arguments.get_phu(),
            inner_arguments.get_t_hat(),
            &u,
        )
        .verify_proof_multiscalar(&inner_proof);

        let proof_check: bool =
            range_proof_result.is_ok() && inner_result.is_ok() && inner_multiscalar_result.is_ok();

        if proof_check {
            assert!(true);
        } else {
            panic!("Verifier fails");
        }
    }
}
