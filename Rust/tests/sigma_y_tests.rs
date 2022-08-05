#[cfg(test)]
mod sigma_y_tests {
    use core::panic;

    use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};

    use merlin::Transcript;
    use zeromt::{ElGamal, SigmaYProof, SigmaYProver, SigmaYVerifier, Utils};

    #[test]
    fn verify_sigma_y_test() {
        let mut prover_trans: Transcript = Transcript::new(b"SigmaYTest");
        let mut verifier_trans: Transcript = Transcript::new(b"SigmaYTest");

        let mut rng = ark_std::rand::thread_rng();
        let g: G1Point = Utils::get_n_generators_berkeley(1, &mut rng)[0];
        let r: ScalarField = Utils::get_n_random_scalars_not_zero(1, &mut rng)[0];

        let balance: usize = 100;
        let amounts: Vec<usize> = [1, 2, 3, 4, 5, 5, 4, 2, 2, 4, 5, 3].to_vec();
        let _balance_remaining: usize = balance - amounts.iter().sum::<usize>();

        // Random private keys
        let sender_priv_key: ScalarField = Utils::get_n_random_scalars_not_zero(1, &mut rng)[0];
        let recipients_priv_keys: Vec<ScalarField> =
            Utils::get_n_random_scalars_not_zero(amounts.len(), &mut rng);

        // Public keys
        let sender_pub_key: G1Point = ElGamal::elgamal_calculate_pub_key(&sender_priv_key, &g);
        let recipients_pub_keys: Vec<G1Point> = recipients_priv_keys
            .iter()
            .map(|key: &ScalarField| ElGamal::elgamal_calculate_pub_key(key, &g))
            .collect();

        let c_vec: Vec<G1Point> = amounts
            .iter()
            .map(|a: &usize| ElGamal::elgamal_encrypt(*a, &sender_pub_key, &g, &r).0)
            .collect();

        let c_bar_vec: Vec<G1Point> = amounts
            .iter()
            .zip(recipients_pub_keys.iter())
            .map(|(a, k)| ElGamal::elgamal_encrypt(*a, k, &g, &r).0)
            .collect();

        let mut prover: SigmaYProver =
            SigmaYProver::new(&mut prover_trans, &r, &sender_pub_key, &recipients_pub_keys);

        let proof: SigmaYProof = prover.generate_proof(&mut rng);

        let mut verifier: SigmaYVerifier = SigmaYVerifier::new(
            &mut verifier_trans,
            &sender_pub_key,
            &recipients_pub_keys,
            &c_vec,
            &c_bar_vec,
        );

        let result = verifier.verify_proof(&proof);

        if result.is_ok() {
            assert!(true);
        } else {
            panic!("Verifier fails");
        }
    }
}
