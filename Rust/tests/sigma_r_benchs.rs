#[cfg(test)]
mod sigma_r_benchs {
    use core::panic;

    use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
    use ark_ec::{AffineCurve, ProjectiveCurve};
    use ark_ff::PrimeField;
    use ark_serialize::CanonicalSerialize;
    use merlin::Transcript;
    use serial_test::serial;
    use std::io::Error;
    use zeromt::{ExecTimeBenchmark, SigmaRProof, SigmaRProver, SigmaRVerifier, Utils};

    #[test]
    #[serial]
    fn verify_sigma_r_bench() {
        let mut bench: ExecTimeBenchmark = ExecTimeBenchmark::new(
            "./benchmark/sigma_r.csv".to_string(),
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
            let mut prover_trans: Transcript = Transcript::new(b"SigmaRBench");
            let mut verifier_trans: Transcript = Transcript::new(b"SigmaRBench");


            let r: ScalarField = Utils::get_n_random_scalars(1, &mut rng)[0];
            let g: G1Point = Utils::get_curve_generator();
            let d: G1Point = g.mul(r.into_repr()).into_affine();

            let mut proof: Option<SigmaRProof> = None;
            let mut result: Option<Result<(), Error>> = None;

            bench.bench_function(true, format!("m = {}", m), &mut || {
                proof = Some(SigmaRProver::new(&mut prover_trans, &g, &r).generate_proof(&mut rng));

                [proof.as_ref().unwrap().serialized_size().to_string()].to_vec()
            });

            bench.bench_function(false, "".to_string(), &mut || {
                result = Some(
                    SigmaRVerifier::new(&mut verifier_trans, &g, &d)
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
