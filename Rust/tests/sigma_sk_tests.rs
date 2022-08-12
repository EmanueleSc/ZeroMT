#[cfg(test)]
mod sigma_sk_tests {

    use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
    use ark_ec::{AffineCurve, ProjectiveCurve};
    use ark_ff::PrimeField;
    use merlin::Transcript;
    use zeromt::{SigmaSKProof, SigmaSKProver, SigmaSKVerifier, Utils};
    #[test]
    fn verify_sigma_sk_test() {
        let mut prover_trans: Transcript = Transcript::new(b"SigmaSKTest");
        let mut verifier_trans: Transcript = Transcript::new(b"SigmaSKTest");

        let mut rng = ark_std::rand::thread_rng();

        let n_increases: usize = 2;
        let m_increases: usize = 5;
        let mut _n: usize = 16;
        for _ in 0..=n_increases {
            let mut _m: usize = 2;
            for _ in 0..=m_increases {
                let sk: ScalarField = Utils::get_n_random_scalars(1, &mut rng)[0];
                let g: G1Point = Utils::get_curve_generator();
                let y: G1Point = g.mul(sk.into_repr()).into_affine();

                let mut prover: SigmaSKProver = SigmaSKProver::new(&mut prover_trans, &g, &sk);

                let proof: SigmaSKProof = prover.generate_proof(&mut rng);

                let mut verifier: SigmaSKVerifier =
                    SigmaSKVerifier::new(&mut verifier_trans, &g, &y);
                let result = verifier.verify_proof(&proof);

                assert!(result.is_ok(), "Verifier fails");

                _m *= 2;
            }
            _n *= 2;
        }
    }
}
