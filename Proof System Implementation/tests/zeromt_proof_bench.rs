#[cfg(test)]
mod zeromt_proof_tests {
    use std::time::{Duration, Instant};

    use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
    use ark_serialize::CanonicalSerialize;
    use merlin::Transcript;
    use num_format::{Locale, ToFormattedString};
    use serial_test::serial;
    use zeromt::{
        CsvUtils, ElGamal, InnerProof, InnerProver, InnerVerifier, PolyCoefficients, RangeProof,
        RangeProver, RangeVerifier, SigmaABProof, SigmaABProver, SigmaABVerifier, SigmaRProof,
        SigmaRProver, SigmaRVerifier, SigmaSKProof, SigmaSKProver, SigmaSKVerifier, SigmaYProof,
        SigmaYProver, SigmaYVerifier, Utils,
    };

    #[test]
    #[serial]
    fn zeromt_proof_bench() {
        let mut bench: CsvUtils = CsvUtils::new(
            "./benchmark/zeromt.csv".to_string(),
            [
                "n".to_string(),
                "m".to_string(),
                "range_prover_time_ms".to_string(),
                "range_verifier_time_ms".to_string(),
                "range_proof_size_bytes".to_string(),
                "ipa_prover_time_ms".to_string(),
                "ipa_verifier_time_ms".to_string(),
                "ipa_proof_size_bytes".to_string(),
                "sigma_ab_prover_time_ms".to_string(),
                "sigma_ab_verifier_time_ms".to_string(),
                "sigma_ab_proof_size_bytes".to_string(),
                "sigma_r_prover_time_ms".to_string(),
                "sigma_r_verifier_time_ms".to_string(),
                "sigma_r_proof_size_bytes".to_string(),
                "sigma_sk_prover_time_ms".to_string(),
                "sigma_sk_verifier_time_ms".to_string(),
                "sigma_sk_proof_size_bytes".to_string(),
                "sigma_y_prover_time_ms".to_string(),
                "sigma_y_verifier_time_ms".to_string(),
                "sigma_y_proof_size_bytes".to_string(),
                "total_prover_time_ms".to_string(),
                "total_verifier_time_ms".to_string(),
                "total_proof_size_bytes".to_string(),
            ]
            .to_vec(),
        );

        let n_increases: usize = 2;
        let m_increases: usize = 5;

        let mut rng = ark_std::rand::thread_rng();

        let mut n: usize = 16;
        for _ in 0..=n_increases {
            let mut m: usize = 2;
            for _ in 0..=m_increases {
                let mut total_prove_time: u128 = 0;
                let mut total_verify_time: u128 = 0;
                let mut total_proof_size: usize = 0;

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

                // Proofs generation
                let start = Instant::now();
                let mut range_prover: RangeProver =
                    RangeProver::new(&g, &h, remaining_balance, &amounts, &g_vec, &h_vec, n);

                let (
                    range_proof,
                    l_poly_vec,
                    r_poly_vec,
                    x_prover,
                    y_prover,
                    z_prover,
                    t_coefficients,
                ): (
                    RangeProof,
                    Vec<ScalarField>,
                    Vec<ScalarField>,
                    ScalarField,
                    ScalarField,
                    ScalarField,
                    PolyCoefficients,
                ) = range_prover.generate_proof(&mut rng, &mut prover_trans);
                let range_prover_duration: Duration = start.elapsed();

                let start = Instant::now();
                let sigma_sk_proof: SigmaSKProof = SigmaSKProver::new(&g, &sender_priv_key)
                    .generate_proof(&mut rng, &mut prover_trans);
                let sigma_sk_prover_duration: Duration = start.elapsed();

                let start = Instant::now();
                let sigma_r_proof: SigmaRProof =
                    SigmaRProver::new(&g, &r).generate_proof(&mut rng, &mut prover_trans);
                let sigma_r_prover_duration: Duration = start.elapsed();

                let start = Instant::now();
                let sigma_ab_proof: SigmaABProof =
                    SigmaABProver::new(&g, &d, &c_r, remaining_balance, &amounts, &sender_priv_key)
                        .generate_proof(&mut rng, &mut prover_trans);
                let sigma_ab_prover_duration: Duration = start.elapsed();

                let start = Instant::now();
                let sigma_y_proof: SigmaYProof =
                    SigmaYProver::new(&r, &sender_pub_key, &recipients_pub_keys)
                        .generate_proof(&mut rng, &mut prover_trans);
                let sigma_y_prover_duration: Duration = start.elapsed();

                // Proofs verification
                let start = Instant::now();
                let mut range_verifier: RangeVerifier = RangeVerifier::new(&g, &h, m, n);

                let (range_proof_result, x_verifier, y_verifier, z_verifier) =
                    range_verifier.verify_proof(&range_proof, &mut verifier_trans);
                let range_verifier_duration: Duration = start.elapsed();

                let start = Instant::now();
                let sigma_sk_result = SigmaSKVerifier::new(&g, &sender_pub_key)
                    .verify_proof(&sigma_sk_proof, &mut verifier_trans);
                let sigma_sk_verifier_duration: Duration = start.elapsed();

                let start = Instant::now();
                let sigma_r_result =
                    SigmaRVerifier::new(&g, &d).verify_proof(&sigma_r_proof, &mut verifier_trans);
                let sigma_r_verifier_duration: Duration = start.elapsed();

                let start = Instant::now();
                let sigma_ab_result = SigmaABVerifier::new(&g, &d, &c_r, &c_l, &c_vec)
                    .verify_proof(&sigma_ab_proof, &mut verifier_trans);
                let sigma_ab_verifier_duration: Duration = start.elapsed();

                let start = Instant::now();
                let sigma_y_result =
                    SigmaYVerifier::new(&sender_pub_key, &recipients_pub_keys, &c_vec, &c_bar_vec)
                        .verify_proof(&sigma_y_proof, &mut verifier_trans);
                let sigma_y_verifier_duration: Duration = start.elapsed();

                let start = Instant::now();
                let (h_first_vec_prover, phu_prover): (Vec<G1Point>, G1Point) = range_prover
                    .get_ipa_arguments(
                        &x_prover,
                        &y_prover,
                        &z_prover,
                        range_proof.get_mu(),
                        range_proof.get_a(),
                        range_proof.get_s(),
                        &h,
                        &g_vec,
                        &h_vec,
                    );

                let inner_proof: InnerProof = InnerProver::new(
                    &g_vec,
                    &h_first_vec_prover,
                    &phu_prover,
                    range_proof.get_t_hat(),
                    &l_poly_vec,
                    &r_poly_vec,
                    &u,
                )
                .generate_proof(&mut prover_trans);
                let inner_prover_duration: Duration = start.elapsed();

                let start = Instant::now();

                let (h_first_vec_verifier, phu_verifier): (Vec<G1Point>, G1Point) = range_verifier
                    .get_ipa_arguments(
                        &x_verifier,
                        &y_verifier,
                        &z_verifier,
                        range_proof.get_mu(),
                        range_proof.get_a(),
                        range_proof.get_s(),
                        &h,
                        &g_vec,
                        &h_vec,
                    );

                let inner_result = InnerVerifier::new(
                    &g_vec,
                    &h_first_vec_verifier,
                    &phu_verifier,
                    range_proof.get_t_hat(),
                    &u,
                )
                .verify_proof_multiscalar(&inner_proof, &mut verifier_trans);
                let inner_verifier_duration: Duration = start.elapsed();

                let proof_check: bool = range_proof_result.is_ok()
                    && sigma_sk_result.is_ok()
                    && sigma_r_result.is_ok()
                    && sigma_ab_result.is_ok()
                    && sigma_y_result.is_ok()
                    && inner_result.is_ok();

                assert!(proof_check, "Verifier fails");

                total_prove_time += range_prover_duration.as_millis()
                    + inner_prover_duration.as_millis()
                    + sigma_ab_prover_duration.as_millis()
                    + sigma_sk_prover_duration.as_millis()
                    + sigma_r_prover_duration.as_millis()
                    + sigma_y_prover_duration.as_millis();

                total_verify_time += range_verifier_duration.as_millis()
                    + inner_verifier_duration.as_millis()
                    + sigma_ab_verifier_duration.as_millis()
                    + sigma_sk_verifier_duration.as_millis()
                    + sigma_r_verifier_duration.as_millis()
                    + sigma_y_verifier_duration.as_millis();

                total_proof_size += range_proof.uncompressed_size()
                    + (inner_proof.uncompressed_size())
                    + sigma_ab_proof.uncompressed_size()
                    + sigma_sk_proof.uncompressed_size()
                    + sigma_r_proof.uncompressed_size()
                    + sigma_y_proof.uncompressed_size();

                bench.write_content(
                    [
                        n.to_string(),
                        m.to_string(),
                        range_prover_duration
                            .as_millis()
                            .to_formatted_string(&Locale::en),
                        range_verifier_duration
                            .as_millis()
                            .to_formatted_string(&Locale::en),
                        range_proof
                            .uncompressed_size()
                            .to_formatted_string(&Locale::en),
                        inner_prover_duration
                            .as_millis()
                            .to_formatted_string(&Locale::en),
                        inner_verifier_duration
                            .as_millis()
                            .to_formatted_string(&Locale::en),
                        (inner_proof.uncompressed_size()).to_formatted_string(&Locale::en),
                        sigma_ab_prover_duration
                            .as_millis()
                            .to_formatted_string(&Locale::en),
                        sigma_ab_verifier_duration
                            .as_millis()
                            .to_formatted_string(&Locale::en),
                        sigma_ab_proof
                            .uncompressed_size()
                            .to_formatted_string(&Locale::en),
                        sigma_r_prover_duration
                            .as_millis()
                            .to_formatted_string(&Locale::en),
                        sigma_r_verifier_duration
                            .as_millis()
                            .to_formatted_string(&Locale::en),
                        sigma_r_proof
                            .uncompressed_size()
                            .to_formatted_string(&Locale::en),
                        sigma_sk_prover_duration
                            .as_millis()
                            .to_formatted_string(&Locale::en),
                        sigma_sk_verifier_duration
                            .as_millis()
                            .to_formatted_string(&Locale::en),
                        sigma_sk_proof
                            .uncompressed_size()
                            .to_formatted_string(&Locale::en),
                        sigma_y_prover_duration
                            .as_millis()
                            .to_formatted_string(&Locale::en),
                        sigma_y_verifier_duration
                            .as_millis()
                            .to_formatted_string(&Locale::en),
                        sigma_y_proof
                            .uncompressed_size()
                            .to_formatted_string(&Locale::en),
                        total_prove_time.to_formatted_string(&Locale::en),
                        total_verify_time.to_formatted_string(&Locale::en),
                        total_proof_size.to_formatted_string(&Locale::en),
                    ]
                    .to_vec(),
                );

                bench.next_line();

                m *= 2;
            }
            n *= 2;
        }
    }
}
