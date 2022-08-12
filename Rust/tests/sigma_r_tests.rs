#[cfg(test)]
mod sigma_r_tests {

    use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
    use ark_ec::{AffineCurve, ProjectiveCurve};
    use ark_ff::PrimeField;
    use merlin::Transcript;
    use zeromt::{SigmaRProof, SigmaRProver, SigmaRVerifier, Utils};
    #[test]
    fn verify_sigma_r_test() {
        let mut prover_trans: Transcript = Transcript::new(b"SigmaRTest");
        let mut verifier_trans: Transcript = Transcript::new(b"SigmaRTest");

        let mut rng = ark_std::rand::thread_rng();

        let n_increases: usize = 2;
        let m_increases: usize = 5;
        let mut _n: usize = 16;
        for _ in 0..=n_increases {
            let mut _m: usize = 2;
            for _ in 0..=m_increases {
                let r: ScalarField = Utils::get_n_random_scalars(1, &mut rng)[0];
                let g: G1Point = Utils::get_curve_generator();
                let d: G1Point = g.mul(r.into_repr()).into_affine();

                let mut prover: SigmaRProver = SigmaRProver::new(&mut prover_trans, &g, &r);

                let proof: SigmaRProof = prover.generate_proof(&mut rng);

                let mut verifier: SigmaRVerifier = SigmaRVerifier::new(&mut verifier_trans, &g, &d);
                let result = verifier.verify_proof(&proof);

                assert!(result.is_ok(), "Verifier fails");

                _m *= 2;
            }
            _n *= 2;
        }
    }
}
