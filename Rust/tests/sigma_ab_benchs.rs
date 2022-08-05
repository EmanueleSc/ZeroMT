#[cfg(test)]
mod sigma_ab_benchs {
    use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};

    use ark_serialize::CanonicalSerialize;

    use core::panic;
    use merlin::Transcript;
    use serial_test::serial;
    use std::io::Error;
    use zeromt::{ElGamal, ExecTimeBenchmark, SigmaABProof, SigmaABProver, SigmaABVerifier, Utils};

    #[test]
    #[serial]
    fn verify_sigma_ab_bench() {
        let mut bench: ExecTimeBenchmark = ExecTimeBenchmark::new(
            "./benchmark/sigma_ab.csv".to_string(),
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
            let mut prover_trans: Transcript = Transcript::new(b"SigmaABBench");
            let mut verifier_trans: Transcript = Transcript::new(b"SigmaABBench");

            let g: G1Point = Utils::get_n_generators_berkeley(1, &mut rng)[0];
            let r: ScalarField = Utils::get_n_random_scalars_not_zero(1, &mut rng)[0];

            let (total_balance, amounts, balance_remaining) = Utils::get_mock_balances(m, &mut rng);

            // Random private keys
            let sender_priv_key: ScalarField = Utils::get_n_random_scalars_not_zero(1, &mut rng)[0];

            // Public keys
            let sender_pub_key: G1Point = ElGamal::elgamal_calculate_pub_key(&sender_priv_key, &g);

            let (c_l, c_r): (G1Point, G1Point) =
                ElGamal::elgamal_encrypt(total_balance, &sender_pub_key, &g, &r);

            let d: G1Point = ElGamal::elgamal_d(&g, &r);

            let c_vec: Vec<G1Point> = amounts
                .iter()
                .map(|a: &usize| ElGamal::elgamal_encrypt(*a, &sender_pub_key, &g, &r).0)
                .collect();

            let mut proof: Option<SigmaABProof> = None;
            let mut result: Option<Result<(), Error>> = None;

            bench.bench_function(true, format!("m = {}", m), &mut || {
                proof = Some(
                    SigmaABProver::new(
                        &mut prover_trans,
                        &g,
                        &d,
                        &c_r,
                        balance_remaining,
                        &amounts,
                        &sender_priv_key,
                    )
                    .generate_proof(&mut rng),
                );

                [proof.as_ref().unwrap().serialized_size().to_string()].to_vec()
            });

            bench.bench_function(false, "".to_string(), &mut || {
                result = Some(
                    SigmaABVerifier::new(
                        &mut verifier_trans,
                        &g,
                        &d,
                        &c_r,
                        &c_l,
                        &c_vec,
                        amounts.len(),
                    )
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
}
