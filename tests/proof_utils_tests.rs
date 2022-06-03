#[cfg(test)]
mod proof_utils_tests {
    use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
    use ark_ec::short_weierstrass_jacobian::GroupAffine;
    use ark_ff::Zero;
    use zeromt::ProofUtils;
    #[test]
    pub fn number_to_be_bits_test() {
        let test_number: usize = 42;
        let test_number_bits: Vec<u8> = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            1, 0, 1, 0, 1, 0,
        ]
        .to_vec();

        let resulting_number_bits: Vec<u8> = ProofUtils::number_to_be_bits(test_number);

        assert_eq!(test_number_bits, resulting_number_bits);
    }
    #[test]
    pub fn number_to_be_bits_reversed_test() {
        let test_number: usize = 42;
        let mut test_number_bits: Vec<u8> = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            1, 0, 1, 0, 1, 0,
        ]
        .to_vec();

        test_number_bits.reverse();
        let resulting_number_bits: Vec<u8> = ProofUtils::number_to_be_bits_reversed(test_number);

        assert_eq!(test_number_bits, resulting_number_bits);
    }
    #[test]
    pub fn get_a_l_test() {
        let test_balance: usize = 42;
        let test_amounts: Vec<usize> = [1, 2, 3, 4, 5].to_vec();

        let mut test_a_l: Vec<i8> = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            1, 0, 1, 0, 1, 0,
        ]
        .to_vec();
        let mut one_bits = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 1,
        ]
        .to_vec();
        let mut two_bits = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 1, 0,
        ]
        .to_vec();
        let mut three_bits = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 1, 1,
        ]
        .to_vec();
        let mut four_bits = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 1, 0, 0,
        ]
        .to_vec();
        let mut five_bits = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 1, 0, 1,
        ]
        .to_vec();

        test_a_l.reverse();
        one_bits.reverse();
        two_bits.reverse();
        three_bits.reverse();
        four_bits.reverse();
        five_bits.reverse();

        test_a_l.extend(one_bits);
        test_a_l.extend(two_bits);
        test_a_l.extend(three_bits);
        test_a_l.extend(four_bits);
        test_a_l.extend(five_bits);

        let test_a_l_scalar: Vec<ScalarField> =
            test_a_l.iter().map(|bit| ScalarField::from(*bit)).collect();
        let result_a_l: Vec<ScalarField> = ProofUtils::get_a_l(test_balance, &test_amounts);

        assert_eq!(result_a_l, test_a_l_scalar);
    }
    #[test]
    pub fn get_a_r_test() {
        let test_a_l_scalar: Vec<ScalarField> = [1, 0, 1, 1, 0, 0, 0, 0, 1]
            .to_vec()
            .iter()
            .map(|bit| ScalarField::from(*bit))
            .collect();

        let test_a_r_scalar: Vec<ScalarField> = [0, -1, 0, 0, -1, -1, -1, -1, 0]
            .to_vec()
            .iter()
            .map(|bit| ScalarField::from(*bit))
            .collect();

        let result_a_r: Vec<ScalarField> = ProofUtils::get_a_r(&test_a_l_scalar);

        assert_eq!(result_a_r, test_a_r_scalar);
    }
    #[test]
    pub fn inner_product_test() {
        let mut rng = ark_std::rand::thread_rng();
        let test_points: Vec<G1Point> = ProofUtils::get_n_generators_berkeley(2, &mut rng);

        let test_bits_one: Vec<ScalarField> = [1, 1]
            .to_vec()
            .iter()
            .map(|bit| ScalarField::from(*bit))
            .collect();
        let test_bits_two: Vec<ScalarField> = [1, 0]
            .to_vec()
            .iter()
            .map(|bit| ScalarField::from(*bit))
            .collect();
        let test_bits_three: Vec<ScalarField> = [0, 1]
            .to_vec()
            .iter()
            .map(|bit| ScalarField::from(*bit))
            .collect();
        let test_bits_four: Vec<ScalarField> = [0, 0]
            .to_vec()
            .iter()
            .map(|bit| ScalarField::from(*bit))
            .collect();

        let test_bits_minus_one: Vec<ScalarField> = [-1, -1]
            .to_vec()
            .iter()
            .map(|bit| ScalarField::from(*bit))
            .collect();
        let test_bits_minus_two: Vec<ScalarField> = [-1, 0]
            .to_vec()
            .iter()
            .map(|bit| ScalarField::from(*bit))
            .collect();
        let test_bits_minus_three: Vec<ScalarField> = [0, -1]
            .to_vec()
            .iter()
            .map(|bit| ScalarField::from(*bit))
            .collect();

        let test_bits_mix_one: Vec<ScalarField> = [1, -1]
            .to_vec()
            .iter()
            .map(|bit| ScalarField::from(*bit))
            .collect();
        let test_bits_mix_two: Vec<ScalarField> = [-1, 1]
            .to_vec()
            .iter()
            .map(|bit| ScalarField::from(*bit))
            .collect();

        let result_inner_product_one: G1Point =
            ProofUtils::inner_product(&test_points, &test_bits_one).unwrap();
        assert_eq!(result_inner_product_one, test_points[0] + test_points[1]);

        let result_inner_product_two: G1Point =
            ProofUtils::inner_product(&test_points, &test_bits_two).unwrap();
        assert_eq!(
            result_inner_product_two,
            test_points[0] + GroupAffine::zero()
        );

        let result_inner_product_three: G1Point =
            ProofUtils::inner_product(&test_points, &test_bits_three).unwrap();
        assert_eq!(
            result_inner_product_three,
            GroupAffine::zero() + test_points[1]
        );

        let result_inner_product_four: G1Point =
            ProofUtils::inner_product(&test_points, &test_bits_four).unwrap();
        assert_eq!(
            result_inner_product_four,
            GroupAffine::zero() + GroupAffine::zero()
        );

        let result_inner_product_minus_one: G1Point =
            ProofUtils::inner_product(&test_points, &test_bits_minus_one).unwrap();
        assert_eq!(
            result_inner_product_minus_one,
            -test_points[0] + -test_points[1]
        );

        let result_inner_product_minus_two: G1Point =
            ProofUtils::inner_product(&test_points, &test_bits_minus_two).unwrap();
        assert_eq!(
            result_inner_product_minus_two,
            -test_points[0] + GroupAffine::zero()
        );

        let result_inner_product_minus_three: G1Point =
            ProofUtils::inner_product(&test_points, &test_bits_minus_three).unwrap();
        assert_eq!(
            result_inner_product_minus_three,
            GroupAffine::zero() + -test_points[1]
        );

        let result_inner_product_mix_one: G1Point =
            ProofUtils::inner_product(&test_points, &test_bits_mix_one).unwrap();
        assert_eq!(
            result_inner_product_mix_one,
            test_points[0] + -test_points[1]
        );

        let result_inner_product_mix_two: G1Point =
            ProofUtils::inner_product(&test_points, &test_bits_mix_two).unwrap();
        assert_eq!(
            result_inner_product_mix_two,
            -test_points[0] + test_points[1]
        );
    }

    #[test]
    pub fn pedersen_test() {
        let balance: usize = 100;
        let amounts: Vec<usize> = [10, 20, 30, 40, 50].to_vec();
        let mut rng = ark_std::rand::thread_rng();

        let alpha: ScalarField = ProofUtils::get_n_random_scalars(1, &mut rng)[0];
        let rho: ScalarField = ProofUtils::get_n_random_scalars(1, &mut rng)[0];

        let a_l: Vec<ScalarField> = ProofUtils::get_a_l(balance, &amounts);
        let a_r: Vec<ScalarField> = ProofUtils::get_a_r(&a_l);

        let s_l: Vec<ScalarField> =
            ProofUtils::get_n_random_scalars(ProofUtils::get_n_by_m(amounts.len() + 1), &mut rng);
        let s_r: Vec<ScalarField> =
            ProofUtils::get_n_random_scalars(ProofUtils::get_n_by_m(amounts.len() + 1), &mut rng);

        let g_vec: Vec<G1Point> = ProofUtils::get_n_generators_berkeley(
            ProofUtils::get_n_by_m(amounts.len() + 1),
            &mut rng,
        );
        let h_vec: Vec<G1Point> = ProofUtils::get_n_generators_berkeley(
            ProofUtils::get_n_by_m(amounts.len() + 1),
            &mut rng,
        );

        let h = ProofUtils::get_n_random_points(1, &mut rng)[0];

        let a_commitment =
            ProofUtils::pedersen_vector_commitment(&alpha, &h, &a_l, &g_vec, &a_r, &h_vec);

        let s_commitment =
            ProofUtils::pedersen_vector_commitment(&rho, &h, &s_l, &g_vec, &s_r, &h_vec);

        assert!(a_commitment.unwrap().is_on_curve());
        assert!(s_commitment.unwrap().is_on_curve());
    }
}
