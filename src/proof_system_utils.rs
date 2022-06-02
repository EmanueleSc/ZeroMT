use ark_bn254::g1::{G1_GENERATOR_X, G1_GENERATOR_Y};
use ark_bn254::{
    g1::Parameters as G1Parameters, Fq as BaseField, Fr as ScalarField, G1Affine, G1Projective,
};
use ark_crypto_primitives::commitment::pedersen::Window;
use ark_crypto_primitives::crh::pedersen::CRH;
use ark_ec::short_weierstrass_jacobian::GroupAffine;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{One, PrimeField, Zero};
use ark_std::UniformRand;
use rand::Rng;

#[derive(Clone)]
struct MockWindow;

impl Window for MockWindow {
    const WINDOW_SIZE: usize = 1;
    const NUM_WINDOWS: usize = 1;
}
pub struct ProofSystemUtils;

impl ProofSystemUtils {
    // Berkeley solution
    pub fn get_n_generators_berkeley<R: Rng>(
        number_of_generators: usize,
        rng: &mut R,
    ) -> Vec<GroupAffine<G1Parameters>> {
        let gens = CRH::<G1Projective, MockWindow>::generator_powers(number_of_generators, rng)
            .iter()
            .map(|p| p.into_affine())
            .collect::<Vec<GroupAffine<G1Parameters>>>();
        return gens;
    }

    pub fn get_n_random_points<R: Rng>(
        number_of_points: usize,
        rng: &mut R,
    ) -> Vec<GroupAffine<G1Parameters>> {
        let mut points = Vec::<GroupAffine<G1Parameters>>::with_capacity(number_of_points);
        for _ in 0..number_of_points {
            points.push(G1Projective::rand(rng).into_affine());
        }
        return points;
    }

    pub fn get_n_random_scalars<R: Rng>(number_of_points: usize, rng: &mut R) -> Vec<ScalarField> {
        let mut scalars = Vec::<ScalarField>::with_capacity(number_of_points);
        for _ in 0..number_of_points {
            scalars.push(ScalarField::rand(rng));
        }
        return scalars;
    }

    pub fn get_n_random_scalars_not_zero<R: Rng>(
        number_of_points: usize,
        rng: &mut R,
    ) -> Vec<ScalarField> {
        let mut scalars = Vec::<ScalarField>::with_capacity(number_of_points);
        for _ in 0..number_of_points {
            let mut to_push: ScalarField = ScalarField::rand(rng);
            while to_push == ScalarField::zero() {
                to_push = ScalarField::rand(rng);
            }
            scalars.push(to_push);
        }
        return scalars;
    }

    pub fn get_curve_generator() -> GroupAffine<G1Parameters> {
        return G1Affine::new(G1_GENERATOR_X, G1_GENERATOR_Y, false);
    }

    pub fn inner_product(
        points: &Vec<GroupAffine<G1Parameters>>,
        scalars: &Vec<ScalarField>,
    ) -> Result<GroupAffine<G1Parameters>, &'static str> {
        if (points.len() != scalars.len()) {
            return Err("Different lengths! Error!");
        }

        let result: GroupAffine<G1Parameters> = points
            .iter()
            .zip(scalars.iter())
            .map(|(p, s)| {
                return p.mul(s.into_repr()).into_affine();
            })
            .sum();

        return Ok(result);
    }

    // b_scalar * b_point + <g_scalar_vec, g_point_vec> + <h_scalar_vec, h_point_vec>
    pub fn pedersen_vector_commitment(
        b_scalar: &ScalarField,
        b_point: &GroupAffine<G1Parameters>,
        g_scalar_vec: &Vec<ScalarField>,
        g_point_vec: &Vec<GroupAffine<G1Parameters>>,
        h_scalar_vec: &Vec<ScalarField>,
        h_point_vec: &Vec<GroupAffine<G1Parameters>>,
    ) -> Result<GroupAffine<G1Parameters>, &'static str> {
        let first_inner_product = Self::inner_product(g_point_vec, g_scalar_vec);
        let second_inner_product = Self::inner_product(h_point_vec, h_scalar_vec);
        if (first_inner_product.is_err() || second_inner_product.is_err()) {
            return Err("Inner product error!");
        } else {
            return Ok(b_point.mul(b_scalar.into_repr()).into_affine()
                + first_inner_product.unwrap()
                + second_inner_product.unwrap());
        }
    }

    pub fn get_n_by_m(m: usize) -> usize {
        return (usize::BITS as usize) * m;
    }

    pub fn get_n() -> usize {
        return usize::BITS as usize;
    }

    pub fn number_to_be_bits(number: usize) -> Vec<u8> {
        let mut bits: Vec<u8> = Self::number_to_be_bits_reversed(number);
        bits.reverse();
        return bits;
    }

    pub fn number_to_be_bits_reversed(number: usize) -> Vec<u8> {
        let mut bits: Vec<u8> = (0..Self::get_n())
            .map(|i| (((number >> i) & 1) as u8))
            .collect();
        return bits;
    }

    pub fn get_a_L(balance: usize, amounts: &Vec<usize>) -> Vec<ScalarField> {
        let mut bits = Vec::<u8>::with_capacity(Self::get_n_by_m(amounts.len() + 1));
        Self::number_to_be_bits_reversed(balance)
            .iter()
            .for_each(|bit| bits.push(*bit));

        amounts
            .iter()
            .map(|amount| Self::number_to_be_bits_reversed(*amount))
            .for_each(|bit_array| {
                bit_array.iter().for_each(|bit| bits.push(*bit));
            });

        return bits.iter().map(|bit| ScalarField::from(*bit)).collect();
    }

    pub fn get_a_R(a_L: &Vec<ScalarField>) -> Vec<ScalarField> {
        return a_L.iter().map(|bit| *bit - ScalarField::one()).collect();
    }

    pub fn test_number_to_be_bits() {
        let test_number: usize = 42;
        let mut test_number_bits: Vec<u8> = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            1, 0, 1, 0, 1, 0,
        ]
        .to_vec();

        let resulting_number_bits: Vec<u8> = Self::number_to_be_bits(test_number);

        assert_eq!(test_number_bits, resulting_number_bits);
    }

    pub fn test_number_to_be_bits_reversed() {
        let test_number: usize = 42;
        let mut test_number_bits: Vec<u8> = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            1, 0, 1, 0, 1, 0,
        ]
        .to_vec();

        test_number_bits.reverse();
        let resulting_number_bits: Vec<u8> = Self::number_to_be_bits_reversed(test_number);

        assert_eq!(test_number_bits, resulting_number_bits);
    }

    pub fn test_get_a_L() {
        let test_balance: usize = 42;
        let test_amounts: Vec<usize> = [1, 2, 3, 4, 5].to_vec();

        let mut test_a_L: Vec<i8> = [
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

        test_a_L.reverse();
        one_bits.reverse();
        two_bits.reverse();
        three_bits.reverse();
        four_bits.reverse();
        five_bits.reverse();

        test_a_L.extend(one_bits);
        test_a_L.extend(two_bits);
        test_a_L.extend(three_bits);
        test_a_L.extend(four_bits);
        test_a_L.extend(five_bits);

        let test_a_L_scalar: Vec<ScalarField> =
            test_a_L.iter().map(|bit| ScalarField::from(*bit)).collect();
        let result_a_L: Vec<ScalarField> = Self::get_a_L(test_balance, &test_amounts);

        assert_eq!(result_a_L, test_a_L_scalar);
    }

    pub fn test_get_a_R() {
        let test_a_L_scalar: Vec<ScalarField> = [1, 0, 1, 1, 0, 0, 0, 0, 1]
            .to_vec()
            .iter()
            .map(|bit| ScalarField::from(*bit))
            .collect();

        let test_a_R_scalar: Vec<ScalarField> = [0, -1, 0, 0, -1, -1, -1, -1, 0]
            .to_vec()
            .iter()
            .map(|bit| ScalarField::from(*bit))
            .collect();

        let result_a_R: Vec<ScalarField> = Self::get_a_R(&test_a_L_scalar);

        assert_eq!(result_a_R, test_a_R_scalar);
    }

    pub fn test_inner_product() {
        let mut rng = ark_std::rand::thread_rng();
        let test_points: Vec<GroupAffine<G1Parameters>> =
            Self::get_n_generators_berkeley(2, &mut rng);

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

        let result_inner_product_one: GroupAffine<G1Parameters> =
            Self::inner_product(&test_points, &test_bits_one).unwrap();
        assert_eq!(result_inner_product_one, test_points[0] + test_points[1]);

        let result_inner_product_two: GroupAffine<G1Parameters> =
            Self::inner_product(&test_points, &test_bits_two).unwrap();
        assert_eq!(
            result_inner_product_two,
            test_points[0] + GroupAffine::zero()
        );

        let result_inner_product_three: GroupAffine<G1Parameters> =
            Self::inner_product(&test_points, &test_bits_three).unwrap();
        assert_eq!(
            result_inner_product_three,
            GroupAffine::zero() + test_points[1]
        );

        let result_inner_product_four: GroupAffine<G1Parameters> =
            Self::inner_product(&test_points, &test_bits_four).unwrap();
        assert_eq!(
            result_inner_product_four,
            GroupAffine::zero() + GroupAffine::zero()
        );

        let result_inner_product_minus_one: GroupAffine<G1Parameters> =
            Self::inner_product(&test_points, &test_bits_minus_one).unwrap();
        assert_eq!(
            result_inner_product_minus_one,
            -test_points[0] + -test_points[1]
        );

        let result_inner_product_minus_two: GroupAffine<G1Parameters> =
            Self::inner_product(&test_points, &test_bits_minus_two).unwrap();
        assert_eq!(
            result_inner_product_minus_two,
            -test_points[0] + GroupAffine::zero()
        );

        let result_inner_product_minus_three: GroupAffine<G1Parameters> =
            Self::inner_product(&test_points, &test_bits_minus_three).unwrap();
        assert_eq!(
            result_inner_product_minus_three,
            GroupAffine::zero() + -test_points[1]
        );

        let result_inner_product_mix_one: GroupAffine<G1Parameters> =
            Self::inner_product(&test_points, &test_bits_mix_one).unwrap();
        assert_eq!(
            result_inner_product_mix_one,
            test_points[0] + -test_points[1]
        );

        let result_inner_product_mix_two: GroupAffine<G1Parameters> =
            Self::inner_product(&test_points, &test_bits_mix_two).unwrap();
        assert_eq!(
            result_inner_product_mix_two,
            -test_points[0] + test_points[1]
        );
    }

    pub fn l_poly(a_L: &Vec<i8>, z: ScalarField, s_L: Vec<ScalarField>) {
        if (a_L.len() != s_L.len()) {
            todo!()
        }

        // a_L.iter().map(|bit| *bit - z.into_repr())
    }
}
