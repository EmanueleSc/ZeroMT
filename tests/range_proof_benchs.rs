#[cfg(test)]
mod range_proof_benchs {
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
    #[serial]
    fn verify_range_proof_test() {
        let mut bench: ExecTimeBenchmark = ExecTimeBenchmark::new(
            "./benchmark/range_proof.csv".to_string(),
            "m size".to_string(),
            [
                "Prover time (ms)".to_string(),
                "Proof size (bytes)".to_string(),
                "Verifier time (ms)".to_string(),
            ]
            .to_vec(),
        );

        let mut rng = ark_std::rand::thread_rng();

        let m_increases = 6;
        let mut m = 2;

        for _ in 0..m_increases {
            let mut prover_trans: Transcript = Transcript::new(b"RangeProofBench");
            let mut verifier_trans: Transcript = Transcript::new(b"RangeProofBench");
            let g: G1Point = Utils::get_curve_generator();
            let h: G1Point = Utils::get_n_generators_berkeley(1, &mut rng)[0];

            let (total_balance, amounts, balance_remaining) = Utils::get_mock_balances(m, &mut rng);

            let (mut proof, mut inner_arguments): (
                Option<RangeProof>,
                Option<InnerProofArguments>,
            ) = (None, None);

            let mut result: Option<Result<(), Error>> = None;

            bench.bench_function(true, format!("m = {}", m), &mut || {
                let (res_proof, res_inner_arguments) =
                    RangeProver::new(&mut prover_trans, &g, &h, balance_remaining, &amounts)
                        .generate_proof(&mut rng);

                proof = Some(res_proof);
                inner_arguments = Some(res_inner_arguments);

                [proof.as_ref().unwrap().serialized_size().to_string()].to_vec()
            });

            bench.bench_function(false, "".to_string(), &mut || {
                result = Some(
                    RangeVerifier::new(&mut verifier_trans, &g, &h, amounts.len())
                        .verify_proof(proof.as_ref().unwrap()),
                );

                [].to_vec()
            });

            if result.unwrap().is_ok() {
                assert!(true);
            } else {
                panic!("Verifier fails");
            }
            bench.next_line();
            m = m * 2;
        }
    }

    #[test]
    #[serial]
    fn verify_range_proof_with_inner_test() {
        let mut bench: ExecTimeBenchmark = ExecTimeBenchmark::new(
            "./benchmark/range_inner_proof.csv".to_string(),
            "m size".to_string(),
            [
                "Range Prover time (ms)".to_string(),
                "Range Proof size (bytes)".to_string(),
                "Range Verifier time (ms)".to_string(),
                "Inner Prover time (ms)".to_string(),
                "Inner Proof size (bytes)".to_string(),
                "Inner Verifier time (ms)".to_string(),
                "Inner Verifier time multiscalar (ms)".to_string(),
            ]
            .to_vec(),
        );

        // Used for proof sizes calculations
        let empty_vector: Vec<G1Point> = [].to_vec();

        let mut rng = ark_std::rand::thread_rng();

        let m_increases = 6;
        let mut m = 2;

        for _ in 0..m_increases {
            let mut prover_trans: Transcript = Transcript::new(b"RangeProofBench");
            let mut verifier_trans: Transcript = Transcript::new(b"RangeProofBench");

            let g: G1Point = Utils::get_curve_generator();
            let h: G1Point = Utils::get_n_generators_berkeley(1, &mut rng)[0];

            let (total_balance, amounts, balance_remaining) = Utils::get_mock_balances(m, &mut rng);

            let (mut range_proof, mut inner_arguments): (
                Option<RangeProof>,
                Option<InnerProofArguments>,
            ) = (None, None);

            let mut range_result: Option<Result<(), Error>> = None;

            bench.bench_function(true, format!("m = {}", m), &mut || {
                let (res_proof, res_inner_arguments): (RangeProof, InnerProofArguments) =
                    RangeProver::new(&mut prover_trans, &g, &h, balance_remaining, &amounts)
                        .generate_proof(&mut rng);

                range_proof = Some(res_proof);
                inner_arguments = Some(res_inner_arguments);

                [range_proof.as_ref().unwrap().serialized_size().to_string()].to_vec()
            });

            bench.bench_function(false, "".to_string(), &mut || {
                range_result = Some(
                    RangeVerifier::new(&mut verifier_trans, &g, &h, amounts.len())
                        .verify_proof(range_proof.as_ref().unwrap()),
                );

                [].to_vec()
            });

            let mut verifier_multiscalar_trans: Transcript = verifier_trans.clone();

            let u: G1Point = Utils::get_n_generators_berkeley(1, &mut rng)[0];

            let mut inner_proof: Option<InnerProof> = None;
            let mut inner_result: Option<Result<(), Error>> = None;
            let mut inner_result_multiscalar: Option<Result<(), Error>> = None;

            bench.bench_function(false, "".to_string(), &mut || {
                inner_proof = Some(
                    InnerProver::new(
                        &mut prover_trans,
                        inner_arguments.as_ref().unwrap().get_g_vec(),
                        inner_arguments.as_ref().unwrap().get_h_first_vec(),
                        inner_arguments.as_ref().unwrap().get_phu(),
                        inner_arguments.as_ref().unwrap().get_t_hat(),
                        inner_arguments.as_ref().unwrap().get_l(),
                        inner_arguments.as_ref().unwrap().get_r(),
                        &u,
                    )
                    .generate_proof(),
                );

                [(inner_proof.as_ref().unwrap().serialized_size()
                    - 2 * empty_vector.serialized_size())
                .to_string()]
                .to_vec()
            });

            bench.bench_function(false, "".to_string(), &mut || {
                inner_result = Some(
                    InnerVerifier::new(
                        &mut verifier_trans,
                        inner_arguments.as_ref().unwrap().get_g_vec(),
                        inner_arguments.as_ref().unwrap().get_h_first_vec(),
                        inner_arguments.as_ref().unwrap().get_phu(),
                        inner_arguments.as_ref().unwrap().get_t_hat(),
                        &u,
                    )
                    .verify_proof(inner_proof.as_ref().unwrap()),
                );

                [].to_vec()
            });

            bench.bench_function(false, "".to_string(), &mut || {
                inner_result_multiscalar = Some(
                    InnerVerifier::new(
                        &mut verifier_multiscalar_trans,
                        inner_arguments.as_ref().unwrap().get_g_vec(),
                        inner_arguments.as_ref().unwrap().get_h_first_vec(),
                        inner_arguments.as_ref().unwrap().get_phu(),
                        inner_arguments.as_ref().unwrap().get_t_hat(),
                        &u,
                    )
                    .verify_proof_multiscalar(inner_proof.as_ref().unwrap()),
                );

                [].to_vec()
            });

            let proof_check: bool = range_result.unwrap().is_ok()
                && inner_result.unwrap().is_ok()
                && inner_result_multiscalar.unwrap().is_ok();

            if proof_check {
                assert!(true);
            } else {
                panic!("Verifier fails");
            }

            bench.next_line();

            m = m * 2;
        }
    }
}
