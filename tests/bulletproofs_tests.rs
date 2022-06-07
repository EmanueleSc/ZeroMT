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
        let balance: usize = 100;
        let amounts: Vec<usize> = [10, 20, 30, 40, 50].to_vec();

        let mut prover: Prover = Prover::new(&mut prover_trans, &g, balance, &amounts);

        let proof: Proof = prover.generate_proof(&mut rng);

        let mut verifier: Verifier = Verifier::new(&mut verifier_trans);

        let result = verifier.verify_proof(&proof);

        if result.is_ok() {
            assert!(true);
        } else {
            panic!("Verifier fails");
        }
    }
}
