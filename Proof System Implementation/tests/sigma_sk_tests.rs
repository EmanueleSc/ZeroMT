#[cfg(test)]
mod sigma_sk_tests {
    use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
    use merlin::Transcript;
    use std::io::Error;
    use zeromt::{ElGamal, SigmaSKProof, SigmaSKProver, SigmaSKVerifier, Utils};
    #[test]
    fn verify_sigma_sk_test() {
        let mut rng = ark_std::rand::thread_rng();

        let n_increases: usize = 2;
        let m_increases: usize = 5;
        let mut _n: usize = 16;
        for _ in 0..=n_increases {
            let mut prover_trans: Transcript = Transcript::new(b"SigmaSKTest");
            let mut verifier_trans: Transcript = Transcript::new(b"SigmaSKTest");

            let mut _m: usize = 2;
            for _ in 0..=m_increases {
                let sk: ScalarField = Utils::get_n_random_scalars(1, &mut rng)[0];
                let g: G1Point = Utils::get_n_generators(1, &mut rng)[0];
                let y: G1Point = ElGamal::elgamal_calculate_pub_key(&sk, &g);

                let proof: SigmaSKProof =
                    SigmaSKProver::new(&g, &sk).generate_proof(&mut rng, &mut prover_trans);

                let result: Result<(), Error> =
                    SigmaSKVerifier::new(&g, &y).verify_proof(&proof, &mut verifier_trans);

                assert!(result.is_ok(), "Verifier fails");

                _m *= 2;
            }
            _n *= 2;
        }
    }
}
