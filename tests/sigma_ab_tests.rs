#[cfg(test)]
mod sigma_ab_tests {
    use core::panic;

    use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
    use ark_ec::{AffineCurve, ProjectiveCurve};
    use ark_ff::{Field, One, PrimeField, Zero};
    use ark_std::rand::Rng;
    use merlin::Transcript;
    use zeromt::{ElGamal, SigmaABProof, SigmaABProver, SigmaABVerifier, Utils};

    #[test]
    fn verify_sigma_ab_test() {
        let mut prover_trans: Transcript = Transcript::new(b"SigmaABTest");
        let mut verifier_trans: Transcript = Transcript::new(b"SigmaABTest");

        let mut rng = ark_std::rand::thread_rng();
        let g: G1Point = Utils::get_n_generators_berkeley(1, &mut rng)[0];
        let r: ScalarField = Utils::get_n_random_scalars_not_zero(1, &mut rng)[0];

        let balance: usize = 100;
        let amounts: Vec<usize> = [1, 2, 3, 4, 5, 5, 4, 2, 2, 4, 5, 3].to_vec();
        let balance_remaining: usize = balance - amounts.iter().sum::<usize>();

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

        let mut prover: SigmaABProver = SigmaABProver::new(
            &mut prover_trans,
            &g,
            &d,
            &c_r,
            balance_remaining,
            &amounts,
            &sender_priv_key,
        );

        let proof: SigmaABProof = prover.generate_proof(&mut rng);

        let mut verifier: SigmaABVerifier = SigmaABVerifier::new(
            &mut verifier_trans,
            &g,
            &d,
            &c_r,
            &c_l,
            &c_vec,
            amounts.len(),
        );

        let result = verifier.verify_proof(&proof);

        if result.is_ok() {
            assert!(true);
        } else {
            panic!("Verifier fails");
        }
    }
}
