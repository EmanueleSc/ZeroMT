#[cfg(test)]
mod sigma_ab_tests {
    use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
    use merlin::Transcript;
    use std::io::Error;
    use zeromt::{ElGamal, SigmaABProof, SigmaABProver, SigmaABVerifier, Utils};

    #[test]
    fn verify_sigma_ab_test() {
        let mut rng = ark_std::rand::thread_rng();

        let n_increases: usize = 2;
        let m_increases: usize = 5;
        let mut n: usize = 16;
        for _ in 0..=n_increases {
            let mut m: usize = 2;
            for _ in 0..=m_increases {
                let mut prover_trans: Transcript = Transcript::new(b"SigmaABTest");
                let mut verifier_trans: Transcript = Transcript::new(b"SigmaABTest");

                let g: G1Point = Utils::get_n_generators(1, &mut rng)[0];
                let r: ScalarField = Utils::get_n_random_scalars_not_zero(1, &mut rng)[0];

                let (balance, amounts, balance_remaining) =
                    Utils::get_mock_balances(m, n, &mut rng);

                // Random private keys
                let sender_priv_key: ScalarField =
                    Utils::get_n_random_scalars_not_zero(1, &mut rng)[0];

                // Public keys
                let sender_pub_key: G1Point =
                    ElGamal::elgamal_calculate_pub_key(&sender_priv_key, &g);

                let (c_l, c_r): (G1Point, G1Point) =
                    ElGamal::elgamal_encrypt(balance, &sender_pub_key, &g, &r);

                let d: G1Point = ElGamal::elgamal_d(&g, &r);

                let c_vec: Vec<G1Point> = amounts
                    .iter()
                    .map(|a: &usize| ElGamal::elgamal_encrypt(*a, &sender_pub_key, &g, &r).0)
                    .collect();

                let proof: SigmaABProof =
                    SigmaABProver::new(&g, &d, &c_r, balance_remaining, &amounts, &sender_priv_key)
                        .generate_proof(&mut rng, &mut prover_trans);

                let result: Result<(), Error> = SigmaABVerifier::new(&g, &d, &c_r, &c_l, &c_vec)
                    .verify_proof(&proof, &mut verifier_trans);

                assert!(result.is_ok(), "Verifier fails");

                m *= 2;
            }
            n *= 2;
        }
    }
}
