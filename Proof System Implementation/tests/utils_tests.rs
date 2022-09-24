#[cfg(test)]
mod utils_tests {
    use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
    use ark_ec::short_weierstrass_jacobian::GroupAffine;
    use ark_ff::Zero;
    use zeromt::Utils;
    #[test]
    pub fn number_to_be_bits_test() {
        let test_number: usize = 42;
        let test_number_bits: Vec<u8> = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            1, 0, 1, 0, 1, 0,
        ]
        .to_vec();

        let resulting_number_bits: Vec<u8> =
            Utils::number_to_be_bits(test_number, usize::BITS as usize);

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
        let resulting_number_bits: Vec<u8> =
            Utils::number_to_be_bits_reversed(test_number, usize::BITS as usize);

        assert_eq!(test_number_bits, resulting_number_bits);
    }

    #[test]
    pub fn inner_product_point_scalar_test() {
        let mut rng = ark_std::rand::thread_rng();
        let test_points: Vec<G1Point> = Utils::get_n_generators(2, &mut rng);

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
            Utils::inner_product_point_scalar(&test_points, &test_bits_one).unwrap();
        assert_eq!(result_inner_product_one, test_points[0] + test_points[1]);

        let result_inner_product_two: G1Point =
            Utils::inner_product_point_scalar(&test_points, &test_bits_two).unwrap();
        assert_eq!(
            result_inner_product_two,
            test_points[0] + GroupAffine::zero()
        );

        let result_inner_product_three: G1Point =
            Utils::inner_product_point_scalar(&test_points, &test_bits_three).unwrap();
        assert_eq!(
            result_inner_product_three,
            GroupAffine::zero() + test_points[1]
        );

        let result_inner_product_four: G1Point =
            Utils::inner_product_point_scalar(&test_points, &test_bits_four).unwrap();
        assert_eq!(
            result_inner_product_four,
            GroupAffine::zero() + GroupAffine::zero()
        );

        let result_inner_product_minus_one: G1Point =
            Utils::inner_product_point_scalar(&test_points, &test_bits_minus_one).unwrap();
        assert_eq!(
            result_inner_product_minus_one,
            -test_points[0] + -test_points[1]
        );

        let result_inner_product_minus_two: G1Point =
            Utils::inner_product_point_scalar(&test_points, &test_bits_minus_two).unwrap();
        assert_eq!(
            result_inner_product_minus_two,
            -test_points[0] + GroupAffine::zero()
        );

        let result_inner_product_minus_three: G1Point =
            Utils::inner_product_point_scalar(&test_points, &test_bits_minus_three).unwrap();
        assert_eq!(
            result_inner_product_minus_three,
            GroupAffine::zero() + -test_points[1]
        );

        let result_inner_product_mix_one: G1Point =
            Utils::inner_product_point_scalar(&test_points, &test_bits_mix_one).unwrap();
        assert_eq!(
            result_inner_product_mix_one,
            test_points[0] + -test_points[1]
        );

        let result_inner_product_mix_two: G1Point =
            Utils::inner_product_point_scalar(&test_points, &test_bits_mix_two).unwrap();
        assert_eq!(
            result_inner_product_mix_two,
            -test_points[0] + test_points[1]
        );
    }
}
