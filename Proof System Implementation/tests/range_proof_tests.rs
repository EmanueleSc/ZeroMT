#[cfg(test)]
mod range_proof_tests {
    use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
    use merlin::Transcript;
    use serial_test::serial;

    use std::io::Error;
    use zeromt::{
        InnerProof, InnerProver, InnerVerifier, RangeProof, RangeProver, RangeVerifier, Utils,
    };
    #[test]
    #[serial]
    fn verify_range_proof_test() {
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

                let g_vec: Vec<G1Point> = Utils::get_n_generators(m * n, &mut rng);
                let h_vec: Vec<G1Point> = Utils::get_n_generators(m * n, &mut rng);

                let (_balance_start, amounts, balance_remaining) =
                    Utils::get_mock_balances(m, n, &mut rng);

                let (proof, _l_poly_vec, _r_poly_vec, _x, _y, _z): (
                    RangeProof,
                    Vec<ScalarField>,
                    Vec<ScalarField>,
                    ScalarField,
                    ScalarField,
                    ScalarField,
                ) = RangeProver::new(&g, &h, balance_remaining, &amounts, &g_vec, &h_vec, n)
                    .generate_proof(&mut rng, &mut prover_trans);

                let (result, _x, _y, _z): (
                    Result<(), Error>,
                    ScalarField,
                    ScalarField,
                    ScalarField,
                ) = RangeVerifier::new(&g, &h, m, n).verify_proof(&proof, &mut verifier_trans);

                assert!(result.is_ok(), "Verifier fails");

                m *= 2;
            }
            n *= 2;
        }
    }

    #[test]
    #[serial]
    fn verify_range_proof_with_inner_test() {
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

                let (range_proof, l_poly_vec, r_poly_vec, x_prover, y_prover, z_prover): (
                    RangeProof,
                    Vec<ScalarField>,
                    Vec<ScalarField>,
                    ScalarField,
                    ScalarField,
                    ScalarField,
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

                let inner_result: Result<(), Error> = InnerVerifier::new(
                    &g_vec,
                    &h_first_vec_verifier,
                    &phu_verifier,
                    range_proof.get_t_hat(),
                    &u,
                )
                .verify_proof(&inner_proof, &mut verifier_trans);

                let proof_check: bool = range_proof_result.is_ok() && inner_result.is_ok();

                assert!(proof_check, "Verifier fails");

                m *= 2;
            }
            n *= 2;
        }
    }

    #[test]
    #[serial]
    fn verify_range_proof_with_inner_multiscalar_test() {
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

                let (range_proof, l_poly_vec, r_poly_vec, x_prover, y_prover, z_prover): (
                    RangeProof,
                    Vec<ScalarField>,
                    Vec<ScalarField>,
                    ScalarField,
                    ScalarField,
                    ScalarField,
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

                let inner_result: Result<(), Error> = InnerVerifier::new(
                    &g_vec,
                    &h_first_vec_verifier,
                    &phu_verifier,
                    range_proof.get_t_hat(),
                    &u,
                )
                .verify_proof_multiscalar(&inner_proof, &mut verifier_trans);

                let proof_check: bool = range_proof_result.is_ok() && inner_result.is_ok();

                assert!(proof_check, "Verifier fails");

                m *= 2;
            }
            n *= 2;
        }
    }
}
