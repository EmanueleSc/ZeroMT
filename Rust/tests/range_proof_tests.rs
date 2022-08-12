#[cfg(test)]
mod range_proof_tests {
    use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
    use ark_ec::{AffineCurve, ProjectiveCurve};
    use ark_ff::{Field, One, PrimeField};
    use merlin::Transcript;

    use std::io::Error;
    use zeromt::{
        InnerProof, InnerProver, InnerVerifier, RangeProof, RangeProver, RangeVerifier, Utils,
    };
    #[test]
    fn verify_range_proof_test() {
        let mut prover_trans: Transcript = Transcript::new(b"RangeProofTest");
        let mut verifier_trans: Transcript = Transcript::new(b"RangeProofTest");

        let mut rng = ark_std::rand::thread_rng();
        let n_increases: usize = 2;
        let m_increases: usize = 5;
        let mut n: usize = 16;
        for _ in 0..=n_increases {
            let mut m: usize = 2;
            for _ in 0..=m_increases {
                let g: G1Point = Utils::get_curve_generator();
                let h: G1Point = Utils::get_n_generators_berkeley(1, &mut rng)[0];

                let g_vec: Vec<G1Point> = Utils::get_n_generators_berkeley(m * n, &mut rng);
                let h_vec: Vec<G1Point> = Utils::get_n_generators_berkeley(m * n, &mut rng);

                let (_balance_start, amounts, balance_remaining) =
                    Utils::get_mock_balances(m, n, &mut rng);

                let (proof, _t_hat, _l_poly_vec, _r_poly_vec, _x, _y, _z): (
                    RangeProof,
                    ScalarField,
                    Vec<ScalarField>,
                    Vec<ScalarField>,
                    ScalarField,
                    ScalarField,
                    ScalarField,
                ) = RangeProver::new(
                    &mut prover_trans,
                    &g,
                    &h,
                    balance_remaining,
                    &amounts,
                    &g_vec,
                    &h_vec,
                    n,
                )
                .generate_proof(&mut rng);

                let (result, _x, _y, _z) =
                    RangeVerifier::new(&mut verifier_trans, &g, &h, amounts.len(), n)
                        .verify_proof(&proof);

                assert!(result.is_ok(), "Verifier fails");

                m *= 2;
            }
            n *= 2;
        }
    }

    #[test]
    fn verify_range_proof_with_inner_test() {
        let mut prover_trans: Transcript = Transcript::new(b"RangeProofTest");
        let mut verifier_trans: Transcript = Transcript::new(b"RangeProofTest");

        let mut rng = ark_std::rand::thread_rng();
        let n_increases: usize = 2;
        let m_increases: usize = 5;
        let mut n: usize = 16;
        for _ in 0..=n_increases {
            let mut m: usize = 2;
            for _ in 0..=m_increases {
                let g: G1Point = Utils::get_curve_generator();
                let h: G1Point = Utils::get_n_generators_berkeley(1, &mut rng)[0];

                let (_balance_start, amounts, balance_remaining) =
                    Utils::get_mock_balances(m, n, &mut rng);

                let g_vec: Vec<G1Point> = Utils::get_n_generators_berkeley(m * n, &mut rng);
                let h_vec: Vec<G1Point> = Utils::get_n_generators_berkeley(m * n, &mut rng);

                let (range_proof, t_hat, l_poly_vec, r_poly_vec, _x, _y, _z): (
                    RangeProof,
                    ScalarField,
                    Vec<ScalarField>,
                    Vec<ScalarField>,
                    ScalarField,
                    ScalarField,
                    ScalarField,
                ) = RangeProver::new(
                    &mut prover_trans,
                    &g,
                    &h,
                    balance_remaining,
                    &amounts,
                    &g_vec,
                    &h_vec,
                    n,
                )
                .generate_proof(&mut rng);

                let (range_proof_result, x, y, z): (
                    Result<(), Error>,
                    ScalarField,
                    ScalarField,
                    ScalarField,
                ) = RangeVerifier::new(&mut verifier_trans, &g, &h, amounts.len(), n)
                    .verify_proof(&range_proof);

                let mut verifier_multiscalar_trans: Transcript = verifier_trans.clone();

                let u: G1Point = Utils::get_n_generators_berkeley(1, &mut rng)[0];

                let h_first_vec: Vec<G1Point> = (0..m * n)
                    .map(|i: usize| {
                        h_vec[i]
                            .mul(y.pow([(i as u64)]).inverse().unwrap().into_repr())
                            .into_affine()
                    })
                    .collect();

                let p: G1Point = *range_proof.get_a()
                    + range_proof.get_s().mul(x.into_repr()).into_affine()
                    + -Utils::inner_product_point_scalar(
                        &g_vec,
                        &Utils::generate_scalar_exp_vector(m * n, &ScalarField::one()),
                    )
                    .unwrap()
                    .mul((z).into_repr())
                    .into_affine()
                    + Utils::inner_product_point_scalar(
                        &h_first_vec,
                        &Utils::generate_scalar_exp_vector(m * n, &y),
                    )
                    .unwrap()
                    .mul((z).into_repr())
                    .into_affine()
                    + (1..=m)
                        .map(|j: usize| {
                            Utils::inner_product_point_scalar(
                                &h_first_vec[((j - 1) * n)..(j * n)].to_vec(),
                                &Utils::generate_scalar_exp_vector(n, &ScalarField::from(2)),
                            )
                            .unwrap()
                            .mul((z.pow([1 + (j as u64)])).into_repr())
                            .into_affine()
                        })
                        .sum::<G1Point>();
                let phu: G1Point = p + -h.mul(range_proof.get_mu().into_repr()).into_affine();

                let inner_proof: InnerProof = InnerProver::new(
                    &mut prover_trans,
                    &g_vec,
                    &h_first_vec,
                    &phu,
                    &t_hat,
                    &l_poly_vec,
                    &r_poly_vec,
                    &u,
                )
                .generate_proof();

                let inner_result =
                    InnerVerifier::new(&mut verifier_trans, &g_vec, &h_first_vec, &phu, &t_hat, &u)
                        .verify_proof(&inner_proof);

                let inner_multiscalar_result = InnerVerifier::new(
                    &mut verifier_multiscalar_trans,
                    &g_vec,
                    &h_first_vec,
                    &phu,
                    &t_hat,
                    &u,
                )
                .verify_proof_multiscalar(&inner_proof);

                let proof_check: bool = range_proof_result.is_ok()
                    && inner_result.is_ok()
                    && inner_multiscalar_result.is_ok();

                assert!(proof_check, "Verifier fails");

                m *= 2;
            }
            n *= 2;
        }
    }
}
