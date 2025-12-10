#[cfg(test)]
mod tests {
    use std::{
        io::Error,
        time::{Duration, Instant},
    };
    use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
    use ark_ec::{AffineCurve, ProjectiveCurve};
    use ark_ff::{Field, One, PrimeField};
    use merlin::Transcript;
    use num_format::{Locale, ToFormattedString};
    use serial_test::serial;
    use zeromt::{CsvUtils, InnerProof, InnerProver, InnerVerifier, InnerSigmaProof, InnerSigmaProver, InnerSigmaVerifier, PolyCoefficients, RangeProof, RangeProver,
        RangeVerifier, Utils};

    #[test]
    #[serial]
    fn inner_sigma_range_tests() {
        let mut rng = ark_std::rand::thread_rng();
        let n_increases: usize = 2;
        let m_increases: usize = 5;
        let mut n: usize = 16;

        for _ in 0..=n_increases {
            let mut m: usize = 2;

            for _ in 0..=m_increases {
                let mut prover_trans: Transcript = Transcript::new(b"RangeProofTest");
                let mut verifier_trans: Transcript = Transcript::new(b"RangeProofTest");

                let g: G1Point = Utils::get_n_generators(1, &mut rng)[0];
                let h: G1Point = Utils::get_n_generators(1, &mut rng)[0];

                let (_balance_start, amounts, balance_remaining) =
                    Utils::get_mock_balances(m, n, &mut rng);

                let g_vec: Vec<G1Point> = Utils::get_n_generators(m * n, &mut rng);
                let h_vec: Vec<G1Point> = Utils::get_n_generators(m * n, &mut rng);

                let mut range_prover: RangeProver =
                    RangeProver::new(&g, &h, balance_remaining, &amounts, &g_vec, &h_vec, n);

                let mut range_verifier: RangeVerifier = RangeVerifier::new(&g, &h, m, n);

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

                let (range_proof_result, x_verifier, y_verifier, _z_verifier): (
                    Result<(), Error>,
                    ScalarField,
                    ScalarField,
                    ScalarField,
                ) = range_verifier.verify_proof(&range_proof, &mut verifier_trans);

                let u: G1Point = Utils::get_n_generators(1, &mut rng)[0];

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

                let (h_first_vec_verifier, phu_verifier): (Vec<G1Point>, G1Point) = range_verifier
                    .get_ipa_arguments(
                        &x_verifier,
                        &y_verifier,
                        &z_prover,
                        range_proof.get_mu(),
                        range_proof.get_a(),
                        range_proof.get_s(),
                        &h,
                        &g_vec,
                        &h_vec,
                    );

                let inner_sigma_proof: InnerSigmaProof = InnerSigmaProver::new(
                    &g_vec,
                    &h_first_vec_prover,
                    &phu_prover,
                    range_proof.get_t_hat(),
                    &l_poly_vec,
                    &r_poly_vec,
                    &u,
                )
                .generate_proof(&mut prover_trans);

                let inner_sigma_result: Result<(), Error> = InnerSigmaVerifier::new(
                    &g_vec,
                    &h_first_vec_verifier,
                    &phu_verifier,
                    range_proof.get_t_hat(),
                    &u,
                )
                .verify_proof(&inner_sigma_proof, &mut verifier_trans);

                let proof_check: bool = range_proof_result.is_ok() && inner_sigma_result.is_ok();

                assert!(proof_check, "Verifier fails");

                m *= 2;
            }
            n *= 2;
        }
    }

    #[test]
    #[serial]
    fn inner_sigma_range_multiexp_tests() {
        let mut rng = ark_std::rand::thread_rng();
        let n_increases: usize = 2;
        let m_increases: usize = 5;
        let mut n: usize = 16;

        for _ in 0..=n_increases {
            let mut m: usize = 2;

            for _ in 0..=m_increases {
                let mut prover_trans: Transcript = Transcript::new(b"RangeProofTest");
                let mut verifier_trans: Transcript = Transcript::new(b"RangeProofTest");

                let g: G1Point = Utils::get_n_generators(1, &mut rng)[0];
                let h: G1Point = Utils::get_n_generators(1, &mut rng)[0];

                let (_balance_start, amounts, balance_remaining) =
                    Utils::get_mock_balances(m, n, &mut rng);

                let g_vec: Vec<G1Point> = Utils::get_n_generators(m * n, &mut rng);
                let h_vec: Vec<G1Point> = Utils::get_n_generators(m * n, &mut rng);

                let mut range_prover: RangeProver =
                    RangeProver::new(&g, &h, balance_remaining, &amounts, &g_vec, &h_vec, n);

                let mut range_verifier: RangeVerifier = RangeVerifier::new(&g, &h, m, n);

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

                let (range_proof_result, x_verifier, y_verifier, _z_verifier): (
                    Result<(), Error>,
                    ScalarField,
                    ScalarField,
                    ScalarField,
                ) = range_verifier.verify_proof(&range_proof, &mut verifier_trans);

                let u: G1Point = Utils::get_n_generators(1, &mut rng)[0];

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

                let (h_first_vec_verifier, phu_verifier): (Vec<G1Point>, G1Point) = range_verifier
                    .get_ipa_arguments(
                        &x_verifier,
                        &y_verifier,
                        &z_prover,
                        range_proof.get_mu(),
                        range_proof.get_a(),
                        range_proof.get_s(),
                        &h,
                        &g_vec,
                        &h_vec,
                    );

                let inner_sigma_proof: InnerSigmaProof = InnerSigmaProver::new(
                    &g_vec,
                    &h_first_vec_prover,
                    &phu_prover,
                    range_proof.get_t_hat(),
                    &l_poly_vec,
                    &r_poly_vec,
                    &u,
                )
                .generate_proof(&mut prover_trans);

                let inner_sigma_result: Result<(), Error> = InnerSigmaVerifier::new(
                    &g_vec,
                    &h_first_vec_verifier,
                    &phu_verifier,
                    range_proof.get_t_hat(),
                    &u,
                )
                .verify_proof_multiscalar(&inner_sigma_proof, &mut verifier_trans);

                let proof_check: bool = range_proof_result.is_ok() && inner_sigma_result.is_ok();

                assert!(proof_check, "Verifier fails");

                m *= 2;
            }
            n *= 2;
        }
    }

    #[test]
    #[serial]
    fn inner_bp_vs_inner_sigma_range_tests() {
        let mut bench: CsvUtils = CsvUtils::new(
            "./benchmark/ipa_comparison.csv".to_string(),
            [
                "n".to_string(),
                "m".to_string(),
                "ipa_bulletproofs_prover_time_ms".to_string(),
                "ipa__bulletproofs_verifier_time_ms".to_string(),
                "ipa_sigma_prover_time_ms".to_string(),
                "ipa_sigma_verifier_time_ms".to_string(),
                "ipa_sigma_verifier_multiexp_time_ms".to_string(),
            ]
            .to_vec(),
        );

        let mut rng = ark_std::rand::thread_rng();
        let n_increases: usize = 2;
        let m_increases: usize = 5;
        let mut n: usize = 16;

        for _ in 0..=n_increases {
            let mut m: usize = 2;

            for _ in 0..=m_increases {
                let mut prover_trans: Transcript = Transcript::new(b"RangeProofTest");
                let mut verifier_trans: Transcript = Transcript::new(b"RangeProofTest");

                let g: G1Point = Utils::get_n_generators(1, &mut rng)[0];
                let h: G1Point = Utils::get_n_generators(1, &mut rng)[0];

                let (_balance_start, amounts, balance_remaining) =
                    Utils::get_mock_balances(m, n, &mut rng);

                let g_vec: Vec<G1Point> = Utils::get_n_generators(m * n, &mut rng);
                let h_vec: Vec<G1Point> = Utils::get_n_generators(m * n, &mut rng);

                let mut range_prover: RangeProver =
                    RangeProver::new(&g, &h, balance_remaining, &amounts, &g_vec, &h_vec, n);

                let mut range_verifier: RangeVerifier = RangeVerifier::new(&g, &h, m, n);

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

                let (range_proof_result, x_verifier, y_verifier, _z_verifier): (
                    Result<(), Error>,
                    ScalarField,
                    ScalarField,
                    ScalarField,
                ) = range_verifier.verify_proof(&range_proof, &mut verifier_trans);

                let u: G1Point = Utils::get_n_generators(1, &mut rng)[0];

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

                let (h_first_vec_verifier, phu_verifier): (Vec<G1Point>, G1Point) = range_verifier
                    .get_ipa_arguments(
                        &x_verifier,
                        &y_verifier,
                        &z_prover,
                        range_proof.get_mu(),
                        range_proof.get_a(),
                        range_proof.get_s(),
                        &h,
                        &g_vec,
                        &h_vec,
                    );
                

                // Inner Product Bulletproofs
                let start = Instant::now();
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
                let ipa_bp_prover_duration: Duration = start.elapsed();

                let start = Instant::now();
                let inner_result: Result<(), Error> = InnerVerifier::new(
                    &g_vec,
                    &h_first_vec_verifier,
                    &phu_verifier,
                    range_proof.get_t_hat(),
                    &u,
                )
                .verify_proof(&inner_proof, &mut verifier_trans);
                let ipa_bp_verifier_duration: Duration = start.elapsed();

                // Inner Product Sigma
                let start = Instant::now();
                let inner_sigma_proof: InnerSigmaProof = InnerSigmaProver::new(
                    &g_vec,
                    &h_first_vec_prover,
                    &phu_prover,
                    range_proof.get_t_hat(),
                    &l_poly_vec,
                    &r_poly_vec,
                    &u,
                )
                .generate_proof(&mut prover_trans);
                let ipa_sigma_prover_duration: Duration = start.elapsed();


                let start = Instant::now();
                let inner_sigma_result: Result<(), Error> = InnerSigmaVerifier::new(
                    &g_vec,
                    &h_first_vec_verifier,
                    &phu_verifier,
                    range_proof.get_t_hat(),
                    &u,
                )
                .verify_proof(&inner_sigma_proof, &mut verifier_trans);
                let ipa_sigma_verifier_duration: Duration = start.elapsed();

                // Inner Product Sigma MultiExp
                let inner_sigma_multiexp_proof: InnerSigmaProof = InnerSigmaProver::new(
                    &g_vec,
                    &h_first_vec_prover,
                    &phu_prover,
                    range_proof.get_t_hat(),
                    &l_poly_vec,
                    &r_poly_vec,
                    &u,
                )
                .generate_proof(&mut prover_trans);

                let start = Instant::now();
                let inner_sigma_multiexp_result: Result<(), Error> = InnerSigmaVerifier::new(
                    &g_vec,
                    &h_first_vec_verifier,
                    &phu_verifier,
                    range_proof.get_t_hat(),
                    &u,
                )
                .verify_proof_multiscalar(&inner_sigma_multiexp_proof, &mut verifier_trans);
                let ipa_sigma_verifier_multiexp_duration: Duration = start.elapsed();


                let proof_check: bool = range_proof_result.is_ok() 
                    && inner_result.is_ok() 
                    && inner_sigma_result.is_ok()
                    && inner_sigma_multiexp_result.is_ok();

                assert!(proof_check, "Verifier fails");

                bench.write_content(
                    [
                        n.to_string(),
                        m.to_string(),
                        ipa_bp_prover_duration
                            .as_millis()
                            .to_formatted_string(&Locale::en),
                        ipa_bp_verifier_duration
                            .as_millis()
                            .to_formatted_string(&Locale::en),
                        ipa_sigma_prover_duration
                            .as_millis()
                            .to_formatted_string(&Locale::en),
                        ipa_sigma_verifier_duration
                            .as_millis()
                            .to_formatted_string(&Locale::en),
                        ipa_sigma_verifier_multiexp_duration
                            .as_millis()
                            .to_formatted_string(&Locale::en),
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
