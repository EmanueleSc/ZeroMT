#[cfg(test)]
mod sigma_ab_tests {
    use core::panic;

    use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
    use ark_ec::{AffineCurve, ProjectiveCurve};
    use ark_ff::{Field, One, PrimeField, Zero};
    use ark_std::rand::Rng;
    use merlin::Transcript;
    use zeromt::{
        SigmaABProof as Proof, SigmaABProver as Prover, SigmaABVerifier as Verifier, Utils,
    };

    #[test]
    fn verify_sigma_ab_test() {
        let mut prover_trans: Transcript = Transcript::new(b"SigmaABTest");
        let mut verifier_trans: Transcript = Transcript::new(b"SigmaABTest");

        let mut rng = ark_std::rand::thread_rng();
        let g: G1Point = Utils::get_n_generators_berkeley(1, &mut rng)[0];
        let r: ScalarField = Utils::get_n_random_scalars_not_zero(1, &mut rng)[0];
        let z: ScalarField = Utils::get_n_random_scalars(1, &mut rng)[0];

        // Random private keys
        let sender_priv_key: ScalarField = Utils::get_n_random_scalars_not_zero(1, &mut rng)[0];
        let recipients_priv_keys: Vec<ScalarField> =
            Utils::get_n_random_scalars_not_zero(5, &mut rng);

        // Public keys
        let sender_pub_key: G1Point = Utils::elgamal_calculate_pub_key(&sender_priv_key, &g);
        let recipients_pub_keys: Vec<G1Point> = recipients_priv_keys
            .iter()
            .map(|key: &ScalarField| Utils::elgamal_calculate_pub_key(key, &g))
            .collect();

        let balance: usize = 100;
        let amounts: Vec<usize> = [1, 2, 3, 4, 5, 5, 4, 2, 2, 4, 5, 3].to_vec();
        let balance_remaining: usize = balance - amounts.iter().sum::<usize>();

        let (c_l, c_r): (G1Point, G1Point) =
            Utils::elgamal_encrypt(balance, &sender_pub_key, &g, &r);

        let d: G1Point = Utils::elgamal_d(&g, &r);

        let c_vec: Vec<G1Point> = amounts
            .iter()
            .map(|a: &usize| Utils::elgamal_encrypt(*a, &sender_pub_key, &g, &r).0)
            .collect();

        let c_bar_vec: Vec<G1Point> = amounts
            .iter()
            .zip(recipients_pub_keys.iter())
            .map(|(a, k)| Utils::elgamal_encrypt(*a, k, &g, &r).0)
            .collect();

        let mut prover: Prover = Prover::new(
            &mut prover_trans,
            &g,
            &z,
            &d,
            &c_r,
            balance_remaining,
            &amounts,
            &sender_priv_key,
        );

        let proof: Proof = prover.generate_proof(&mut rng);

        let mut verifier: Verifier = Verifier::new(
            &mut verifier_trans,
            &g,
            &d,
            &c_r,
            &c_l,
            &z,
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