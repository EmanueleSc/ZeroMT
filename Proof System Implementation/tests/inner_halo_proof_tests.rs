#[cfg(test)]
mod tests {

    use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
    use ark_ec::{AffineCurve, ProjectiveCurve};
    use ark_ff::{Field, PrimeField, One};
    use serial_test::serial;
    use std::io::Error;
    use zeromt::{ InnerHaloProof, InnerHaloProver, InnerHaloVerifier, Utils};
    use merlin::Transcript;

    #[test]
    #[serial]
    fn inner_halo_proof_tests() {
        let mut prover_trans: Transcript = Transcript::new(b"RangeProofTest");
        let mut verifier_trans: Transcript = Transcript::new(b"RangeProofTest");

        let mut rng = ark_std::rand::thread_rng();
        let t_0 = Utils::get_n_random_scalars_not_zero(1, &mut rng)[0];
        let t_1 = Utils::get_n_random_scalars_not_zero(1, &mut rng)[0];
        let t_2 = Utils::get_n_random_scalars_not_zero(1, &mut rng)[0];
        let t_vec: Vec<ScalarField> = vec![t_0, t_1, t_2];

        let poly_degree: usize = 2;
        let g_vec: Vec<G1Point> = Utils::get_n_generators(poly_degree + 1, &mut rng);
        let h: G1Point = Utils::get_n_generators(1, &mut rng)[0];
        let u: G1Point = Utils::get_n_generators(1, &mut rng)[0];
        
        let rand_r = Utils::get_n_random_scalars_not_zero(1, &mut rng)[0];
        let t_comm: G1Point = Utils::inner_product_point_scalar(&g_vec, &t_vec).unwrap()
                            + h.mul(rand_r.into_repr()).into_affine();

        let rand_x = Utils::get_n_random_scalars_not_zero(1, &mut rng)[0];
        let b_vec: Vec<ScalarField> = vec![ScalarField::one(), rand_x, rand_x.pow([2])];
        let t_hat: ScalarField = Utils::inner_product_scalar_scalar(&t_vec, &b_vec).unwrap();

        let inner_halo_proof: InnerHaloProof = InnerHaloProver::new(
            &g_vec,
            &h,
            &t_comm,
            &rand_r,
            &t_hat,
            &t_vec,
            &b_vec,
            &u
        )
        .generate_proof(&mut prover_trans);

        let inner_halo_result: Result<(), Error> = InnerHaloVerifier::new(
            &g_vec,
            &b_vec,
            &h,
            &t_comm,
            &t_hat,
            &u
        )
        .verify_proof(&inner_halo_proof, &mut verifier_trans);

        let proof_check: bool = inner_halo_result.is_ok();
        assert!(proof_check, "Verifier fails");
    }
}
