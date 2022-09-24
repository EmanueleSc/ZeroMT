#[cfg(test)]
mod sigma_y_tests {
    use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
    use merlin::Transcript;
    use std::io::Error;
    use zeromt::{ElGamal, SigmaYProof, SigmaYProver, SigmaYVerifier, Utils};

    #[test]
    fn verify_sigma_y_test() {
        let mut rng = ark_std::rand::thread_rng();

        let n_increases: usize = 2;
        let m_increases: usize = 5;
        let mut n: usize = 16;
        for _ in 0..=n_increases {
            let mut m: usize = 2;
            for _ in 0..=m_increases {
                let mut prover_trans: Transcript = Transcript::new(b"SigmaYTest");
                let mut verifier_trans: Transcript = Transcript::new(b"SigmaYTest");

                let g: G1Point = Utils::get_n_generators(1, &mut rng)[0];
                let r: ScalarField = Utils::get_n_random_scalars_not_zero(1, &mut rng)[0];

                let (_balance_start, amounts, _balance_remaining) =
                    Utils::get_mock_balances(m, n, &mut rng);

                // Random private keys
                let sender_priv_key: ScalarField =
                    Utils::get_n_random_scalars_not_zero(1, &mut rng)[0];
                let recipients_priv_keys: Vec<ScalarField> =
                    Utils::get_n_random_scalars_not_zero(amounts.len(), &mut rng);

                // Public keys
                let sender_pub_key: G1Point =
                    ElGamal::elgamal_calculate_pub_key(&sender_priv_key, &g);
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

                let proof: SigmaYProof =
                    SigmaYProver::new(&r, &sender_pub_key, &recipients_pub_keys)
                        .generate_proof(&mut rng, &mut prover_trans);

                let result: Result<(), Error> =
                    SigmaYVerifier::new(&sender_pub_key, &recipients_pub_keys, &c_vec, &c_bar_vec)
                        .verify_proof(&proof, &mut verifier_trans);

                assert!(result.is_ok(), "Verifier fails");

                m *= 2;
            }
            n *= 2;
        }
    }
}
