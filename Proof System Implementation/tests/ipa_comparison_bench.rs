#[cfg(test)]
mod zeromt_proof_tests {
    use std::{
        io::Error,
        time::{Duration, Instant},
    };

    use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
    use ark_ec::{AffineCurve, ProjectiveCurve};
    use ark_ff::{Field, One, PrimeField};
    use ark_serialize::CanonicalSerialize;
    use merlin::Transcript;
    use num_format::{Locale, ToFormattedString};
    use serial_test::serial;
    use zeromt::{
        CsvUtils, InnerHaloProof, InnerHaloProver, InnerHaloVerifier, InnerProof, InnerProver,
        InnerVerifier, PolyCoefficients, RangeProof, RangeProver, RangeVerifier, Utils,
    };

    #[test]
    #[serial]
    fn ipa_comparison_bench() {
        let mut bench: CsvUtils = CsvUtils::new(
            "./benchmark/ipa_comparison.csv".to_string(),
            [
                "n".to_string(),
                "m".to_string(),
                "old_ipa_prover_time_ms".to_string(),
                "old_ipa_verifier_time_ms".to_string(),
                "old_ipa_proof_size_bytes".to_string(),
                "halo_ipa_prover_time_ms".to_string(),
                "halo_ipa_verifier_time_ms".to_string(),
                "halo_ipa_proof_size_bytes".to_string(),
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
                let mut prover_trans: Transcript = Transcript::new(b"ZeroMTTest");
                let mut verifier_trans: Transcript = Transcript::new(b"ZeroMTTest");

                let g: G1Point = Utils::get_n_generators(1, &mut rng)[0];
                let h: G1Point = Utils::get_n_generators(1, &mut rng)[0];
                let r: ScalarField = Utils::get_n_random_scalars_not_zero(1, &mut rng)[0];

                let u: G1Point = Utils::get_n_generators(1, &mut rng)[0];

                let g_vec: Vec<G1Point> = Utils::get_n_generators(m * n, &mut rng);

                let poly_degree: usize = 2;
                let halo_ipa_g_vec: Vec<G1Point> =
                    Utils::get_n_generators(poly_degree + 1, &mut rng);
                let h_vec: Vec<G1Point> = Utils::get_n_generators(m * n, &mut rng);

                let (_balance, amounts, remaining_balance) =
                    Utils::get_mock_balances(m, n, &mut rng);

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

                let mut range_verifier: RangeVerifier = RangeVerifier::new(&g, &h, m, n);

                let (range_proof_result, x_verifier, y_verifier, z_verifier) =
                    range_verifier.verify_proof(&range_proof, &mut verifier_trans);

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

                let old_ipa_proof: InnerProof = InnerProver::new(
                    &g_vec,
                    &h_first_vec_prover,
                    &phu_prover,
                    range_proof.get_t_hat(),
                    &l_poly_vec,
                    &r_poly_vec,
                    &u,
                )
                .generate_proof(&mut prover_trans);
                let old_ipa_prover_duration: Duration = start.elapsed();

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

                let old_ipa_result = InnerVerifier::new(
                    &g_vec,
                    &h_first_vec_verifier,
                    &phu_verifier,
                    range_proof.get_t_hat(),
                    &u,
                )
                .verify_proof_multiscalar(&old_ipa_proof, &mut verifier_trans);
                let old_ipa_verifier_duration: Duration = start.elapsed();

                let t_vec: Vec<ScalarField> = vec![
                    *t_coefficients.get_t_0(),
                    *t_coefficients.get_t_1(),
                    *t_coefficients.get_t_2(),
                ];

                let t_comm: G1Point = Utils::inner_product_point_scalar(&halo_ipa_g_vec, &t_vec)
                    .unwrap()
                    + h.mul(r.into_repr()).into_affine();

                let b_vec: Vec<ScalarField> = vec![ScalarField::one(), x_prover, x_prover.pow([2])];
                let new_t_hat: ScalarField =
                    Utils::inner_product_scalar_scalar(&t_vec, &b_vec).unwrap();

                println!(
                    "n = {} - m = {} - Verifica t hat vecchio e nuovo {}",
                    n,
                    m,
                    *range_proof.get_t_hat() == new_t_hat
                );

                let start = Instant::now();
                let halo_ipa_proof: InnerHaloProof = InnerHaloProver::new(
                    &halo_ipa_g_vec,
                    &h,
                    &t_comm,
                    &r,
                    &new_t_hat,
                    &t_vec,
                    &b_vec,
                    &u,
                )
                .generate_proof(&mut prover_trans);
                let halo_ipa_prover_duration: Duration = start.elapsed();

                let start = Instant::now();
                let halo_ipa_result: Result<(), Error> =
                    InnerHaloVerifier::new(&halo_ipa_g_vec, &b_vec, &h, &t_comm, &new_t_hat, &u)
                        .verify_proof(&halo_ipa_proof, &mut verifier_trans);
                let halo_ipa_verifier_duration: Duration = start.elapsed();

                let proof_check: bool =
                    range_proof_result.is_ok() && old_ipa_result.is_ok() && halo_ipa_result.is_ok();

                assert!(proof_check, "Verifier fails");

                bench.write_content(
                    [
                        n.to_string(),
                        m.to_string(),
                        old_ipa_prover_duration
                            .as_millis()
                            .to_formatted_string(&Locale::en),
                        old_ipa_verifier_duration
                            .as_millis()
                            .to_formatted_string(&Locale::en),
                        (old_ipa_proof.uncompressed_size()).to_formatted_string(&Locale::en),
                        halo_ipa_prover_duration
                            .as_millis()
                            .to_formatted_string(&Locale::en),
                        halo_ipa_verifier_duration
                            .as_millis()
                            .to_formatted_string(&Locale::en),
                        (halo_ipa_proof.uncompressed_size()).to_formatted_string(&Locale::en),
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
