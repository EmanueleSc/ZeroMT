#[cfg(test)]
mod sigma_sk_tests {
    use core::panic;

    use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
    use ark_ec::{AffineCurve, ProjectiveCurve};
    use ark_ff::PrimeField;
    use merlin::Transcript;
    use zeromt::{SigmaRProof as Proof, SigmaRProver as Prover, SigmaRVerifier as Verifier, Utils};
    #[test]
    fn verify_sigma_r_test() {
        let mut prover_trans: Transcript = Transcript::new(b"SigmaRTest");
        let mut verifier_trans: Transcript = Transcript::new(b"SigmaRTest");

        let mut rng = ark_std::rand::thread_rng();

        let r: ScalarField = Utils::get_n_random_scalars(1, &mut rng)[0];
        let g: G1Point = Utils::get_curve_generator();
        let d: G1Point = g.mul(r.into_repr()).into_affine();

        let mut prover: Prover = Prover::new(&mut prover_trans, &g, &r);

        let proof: Proof = prover.generate_proof(&mut rng);

        let mut verifier: Verifier = Verifier::new(&mut verifier_trans, &g, &d);
        let result = verifier.verify_proof(&proof);

        if result.is_ok() {
            assert!(true);
        } else {
            panic!("Verifier fails");
        }
    }
}
