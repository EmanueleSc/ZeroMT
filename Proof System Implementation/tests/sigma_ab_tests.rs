#[cfg(test)]
mod sigma_ab_tests {
    use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
    use merlin::Transcript;
    use rand::Rng;
    use zeromt::{ElGamal, SigmaABProof, SigmaABProver, SigmaABVerifier, Utils};

    pub fn get_mock_balances<R: Rng>(
        m: usize,
        n: usize,
        rng: &mut R,
    ) -> (usize, Vec<usize>, usize) {
        let total_balance: usize = (i128::pow(2, n.try_into().unwrap()) - 1) as usize;

        let mut amounts: Vec<usize> = [].to_vec();
        for _ in 1..m {
            let to_add: usize = rng.gen_range(0..total_balance / (m - 1));
            amounts.push(to_add);
        }
        let balance_remaining: usize = total_balance - amounts.iter().sum::<usize>();
        (total_balance, amounts, balance_remaining)
    }

    #[test]
    fn verify_sigma_ab_test() {
        let mut prover_trans: Transcript = Transcript::new(b"SigmaABTest");
        let mut verifier_trans: Transcript = Transcript::new(b"SigmaABTest");

        let mut rng = ark_std::rand::thread_rng();

        let n_increases: usize = 2;
        let m_increases: usize = 5;
        let mut n: usize = 16;
        for _ in 0..=n_increases {
            let mut m: usize = 2;
            for _ in 0..=m_increases {
                let g: G1Point = Utils::get_n_generators_berkeley(1, &mut rng)[0];
                let r: ScalarField = Utils::get_n_random_scalars_not_zero(1, &mut rng)[0];

                let (balance, amounts, balance_remaining) = get_mock_balances(m, n, &mut rng);

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

                let proof: SigmaABProof = SigmaABProver::new(
                    &mut prover_trans,
                    &g,
                    &d,
                    &c_r,
                    balance_remaining,
                    &amounts,
                    &sender_priv_key,
                )
                .generate_proof(&mut rng);

                let result = SigmaABVerifier::new(
                    &mut verifier_trans,
                    &g,
                    &d,
                    &c_r,
                    &c_l,
                    &c_vec,
                    amounts.len(),
                )
                .verify_proof(&proof);

                assert!(result.is_ok(), "Verifier fails");

                m *= 2;
            }
            n *= 2;
        }
    }
}