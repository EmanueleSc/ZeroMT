#[cfg(test)]
mod zeromt_proof_tests {
    use core::panic;

    use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
    use merlin::Transcript;
    use zeromt::{
        InnerProofArguments, RangeProof, RangeProver, RangeVerifier, SigmaABProof, SigmaABProver,
        SigmaABVerifier, SigmaRProof, SigmaRProver, SigmaRVerifier, SigmaSkProof, SigmaSkProver,
        SigmaSkVerifier, SigmaYProof, SigmaYProver, SigmaYVerifier, Utils,
    };
    #[test]
    fn zeromt_proof_test() {
        let mut prover_trans: Transcript = Transcript::new(b"ZeroMTTest");
        let mut verifier_trans: Transcript = Transcript::new(b"ZeroMTTest");

        let mut rng = ark_std::rand::thread_rng();
        let g: G1Point = Utils::get_n_generators_berkeley(1, &mut rng)[0];
        let h: G1Point = Utils::get_n_generators_berkeley(1, &mut rng)[0];
        let r: ScalarField = Utils::get_n_random_scalars_not_zero(1, &mut rng)[0];

        let balance: usize = 400;
        let amounts: Vec<usize> = [80, 20, 70, 10].to_vec();
        let balance_remaining: usize = balance - amounts.iter().sum::<usize>();

        // Random private keys
        let sender_priv_key: ScalarField = Utils::get_n_random_scalars_not_zero(1, &mut rng)[0];
        let recipients_priv_keys: Vec<ScalarField> =
            Utils::get_n_random_scalars_not_zero(amounts.len(), &mut rng);

        // Public keys
        let sender_pub_key: G1Point = Utils::elgamal_calculate_pub_key(&sender_priv_key, &g);
        let recipients_pub_keys: Vec<G1Point> = recipients_priv_keys
            .iter()
            .map(|key: &ScalarField| Utils::elgamal_calculate_pub_key(key, &g))
            .collect();

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

        // Proofs generation
        let (range_proof, inner_arguments): (RangeProof, InnerProofArguments) =
            RangeProver::new(&mut prover_trans, &g, &h, balance_remaining, &amounts)
                .generate_proof(&mut rng);

        let sigma_sk_proof: SigmaSkProof =
            SigmaSkProver::new(&mut prover_trans, &g, &sender_priv_key).generate_proof(&mut rng);

        let sigma_r_proof: SigmaRProof =
            SigmaRProver::new(&mut prover_trans, &g, &r).generate_proof(&mut rng);

        let sigma_ab_proof: SigmaABProof = SigmaABProver::new(
            &mut prover_trans,
            &g,
            &d,
            &c_r,
            balance_remaining,
            &amounts,
            &sender_priv_key,
        )
        .generate_proof(&mut rng);

        let sigma_y_proof: SigmaYProof =
            SigmaYProver::new(&mut prover_trans, &r, &sender_pub_key, &recipients_pub_keys)
                .generate_proof(&mut rng);

        // Proofs verification
        let range_proof_result = RangeVerifier::new(&mut verifier_trans, &g, &h, amounts.len())
            .verify_proof(&range_proof);

        let sigma_sk_result = SigmaSkVerifier::new(&mut verifier_trans, &g, &sender_pub_key)
            .verify_proof(&sigma_sk_proof);

        let sigma_r_result =
            SigmaRVerifier::new(&mut verifier_trans, &g, &d).verify_proof(&sigma_r_proof);

        let sigma_ab_result = SigmaABVerifier::new(
            &mut verifier_trans,
            &g,
            &d,
            &c_r,
            &c_l,
            &c_vec,
            amounts.len(),
        )
        .verify_proof(&sigma_ab_proof);

        let sigma_y_result = SigmaYVerifier::new(
            &mut verifier_trans,
            &sender_pub_key,
            &recipients_pub_keys,
            &c_vec,
            &c_bar_vec,
        )
        .verify_proof(&sigma_y_proof);

        let proof_check: bool = range_proof_result.is_ok()
            && sigma_sk_result.is_ok()
            && sigma_r_result.is_ok()
            && sigma_ab_result.is_ok()
            && sigma_y_result.is_ok();

        if proof_check {
            assert!(true);
        } else {
            panic!("Verifier fails");
        }
    }
}
