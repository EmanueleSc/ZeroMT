#[cfg(test)]
mod sigma_sk_benchs {
    use core::panic;

    use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
    use ark_ec::{AffineCurve, ProjectiveCurve};
    use ark_ff::PrimeField;
    use ark_serialize::CanonicalSerialize;
    use merlin::Transcript;
    use serial_test::serial;
    use std::io::Error;
    use zeromt::{ExecTimeBenchmark, SigmaSKProof, SigmaSKProver, SigmaSKVerifier, Utils};
    #[test]
    #[serial]
    fn verify_sigma_sk_bench() {
        let mut bench: ExecTimeBenchmark = ExecTimeBenchmark::new(
            "./benchmark/sigma_sk.csv".to_string(),
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
            let mut prover_trans: Transcript = Transcript::new(b"SigmaSKBench");
            let mut verifier_trans: Transcript = Transcript::new(b"SigmaSKBench");

            let sk: ScalarField = Utils::get_n_random_scalars(1, &mut rng)[0];
            let g: G1Point = Utils::get_curve_generator();
            let y: G1Point = g.mul(sk.into_repr()).into_affine();

            let mut proof: Option<SigmaSKProof> = None;
            let mut result: Option<Result<(), Error>> = None;

            bench.bench_function(true, format!("m = {}", m), &mut || {
                proof =
                    Some(SigmaSKProver::new(&mut prover_trans, &g, &sk).generate_proof(&mut rng));

                [proof.as_ref().unwrap().serialized_size().to_string()].to_vec()
            });

            bench.bench_function(false, "".to_string(), &mut || {
                result = Some(
                    SigmaSKVerifier::new(&mut verifier_trans, &g, &y)
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
