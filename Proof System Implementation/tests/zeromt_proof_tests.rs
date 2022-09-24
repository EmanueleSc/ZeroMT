#[cfg(test)]
mod zeromt_proof_tests {

    use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
    use merlin::Transcript;
    use serial_test::serial;
    use std::io::Error;
    use zeromt::{ElGamal, Utils, ZeroMTProof, ZeroMTProver, ZeroMTVerifier};

    #[test]
    #[serial]
    fn zeromt_proof_test() {
        let n_increases: usize = 2;
        let m_increases: usize = 5;

        let mut rng = ark_std::rand::thread_rng();

        let mut n: usize = 16;
        for _ in 0..=n_increases {
            let mut m: usize = 2;
            for _ in 0..=m_increases {
                let mut prover_trans: Transcript = Transcript::new(b"ZeroMTTest");
                let mut verifier_trans: Transcript = Transcript::new(b"ZeroMTTest");

                let g: G1Point = Utils::get_n_generators(1, &mut rng)[0];
                let h: G1Point = Utils::get_n_generators(1, &mut rng)[0];
                let r: ScalarField = Utils::get_n_random_scalars_not_zero(1, &mut rng)[0];

                let u: G1Point = Utils::get_n_generators(1, &mut rng)[0];

                let g_vec: Vec<G1Point> = Utils::get_n_generators(m * n, &mut rng);
                let h_vec: Vec<G1Point> = Utils::get_n_generators(m * n, &mut rng);

                let (balance, amounts, remaining_balance) =
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

                let (c_l, c_r): (G1Point, G1Point) =
                    ElGamal::elgamal_encrypt(balance, &sender_pub_key, &g, &r);

                let d: G1Point = ElGamal::elgamal_d(&g, &r);

                let c_vec: Vec<G1Point> = amounts
                    .iter()
                    .map(|a: &usize| ElGamal::elgamal_encrypt(*a, &sender_pub_key, &g, &r).0)
                    .collect();

                let c_bar_vec: Vec<G1Point> = amounts
                    .iter()
                    .zip(recipients_pub_keys.iter())
                    .map(|(a, k)| ElGamal::elgamal_encrypt(*a, k, &g, &r).0)
                    .collect();

                let proof: ZeroMTProof = ZeroMTProver::new(
                    &g,
                    &h,
                    remaining_balance,
                    &amounts,
                    &g_vec,
                    &h_vec,
                    &u,
                    n,
                    &d,
                    &c_r,
                    &sender_priv_key,
                    &r,
                    &sender_pub_key,
                    &recipients_pub_keys,
                )
                .generate_proof(&mut rng, &mut prover_trans);

                let verification_result: Result<(), Error> = ZeroMTVerifier::new(
                    &g,
                    &h,
                    n,
                    &g_vec,
                    &h_vec,
                    &u,
                    &d,
                    &c_r,
                    &c_l,
                    &c_vec,
                    &c_bar_vec,
                    &sender_pub_key,
                    &recipients_pub_keys,
                )
                .verify_proof(&proof, &mut verifier_trans);

                assert!(verification_result.is_ok(), "Verifier fails");

                m *= 2;
            }
            n *= 2;
        }
    }
}
