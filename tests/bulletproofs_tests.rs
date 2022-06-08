#[cfg(test)]
mod bulletproofs_tests {
    use core::panic;

    use ark_bn254::G1Affine as G1Point;
    use merlin::Transcript;
    use zeromt::{
        BulletproofsProof as Proof, BulletproofsProver as Prover, BulletproofsVerifier as Verifier,
        Utils,
    };
    #[test]
    fn verify_bulletproofs_test() {
        let mut prover_trans: Transcript = Transcript::new(b"BulletproofsTest");
        let mut verifier_trans: Transcript = Transcript::new(b"BulletproofsTest");

        let mut rng = ark_std::rand::thread_rng();
        let g: G1Point = Utils::get_curve_generator();
        let h: G1Point = Utils::get_n_generators_berkeley(1, &mut rng)[0];
        let balance: usize = 100;
        let amounts: Vec<usize> = [1, 2, 3, 4, 5, 5, 4, 2, 2, 4, 5, 3].to_vec();
        let balance_remaining: usize = balance - amounts.iter().sum::<usize>();

        let mut prover: Prover =
            Prover::new(&mut prover_trans, &g, &h, balance_remaining, &amounts);

        let proof: Proof = prover.generate_proof(&mut rng);

        let mut verifier: Verifier = Verifier::new(&mut verifier_trans, &g, &h, amounts.len());

        let result = verifier.verify_proof(&proof);

        if result.is_ok() {
            assert!(true);
        } else {
            panic!("Verifier fails");
        }
    }
}
