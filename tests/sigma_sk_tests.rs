#[cfg(test)]
mod sigma_sk_tests {
    use core::panic;

    use zeromt::ProofUtils;
    use merlin::Transcript;
    use zeromt::Prover;
    use zeromt::Verifier;
    use ark_ff::PrimeField;
    use ark_ec::{AffineCurve, ProjectiveCurve};

    #[test]
    fn verify_sigma_sk_test() {
        let mut prover_trans = Transcript::new(b"SigmaSK");
        let mut verifier_trans = Transcript::new(b"SigmaSK");

        let mut rng = ark_std::rand::thread_rng();
        let sk = ProofUtils::get_n_random_scalars(1, &mut rng)[0];
        let g = ProofUtils::get_curve_generator();
        let y = g.mul(sk.into_repr()).into_affine();
        let mut prover = Prover::new(&mut prover_trans, &g, &y, &sk);
        
        let mut rng = &mut ark_std::test_rng();
        let proof = prover.generate_proof(&mut rng);

        let mut verifier = Verifier::new(&mut verifier_trans, &g, &y);
        let result = verifier.verify_proof(&proof);

        if result.is_ok() {
            assert!(true);
        } else {
            panic!("Verifier fails");
        }
    }
}

