use ark_bn254::g1::{G1_GENERATOR_X, G1_GENERATOR_Y};
use ark_bn254::{
    g1::Parameters as G1Parameters, Fq as BaseField, Fr as ScalarField, G1Affine, G1Projective,
};
use ark_crypto_primitives::commitment::pedersen::Window;
use ark_crypto_primitives::crh::pedersen::CRH;
use ark_ec::short_weierstrass_jacobian::GroupAffine;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{PrimeField, Zero};
use ark_std::UniformRand;
use bitreader::BitReader;
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

    pub fn bit_inner_product(
        points: &Vec<GroupAffine<G1Parameters>>,
        bits: &Vec<i8>,
    ) -> Result<GroupAffine<G1Parameters>, &'static str> {
        if points.len() != bits.len() {
            return Err("Different lengths! Error!");
        } else {
            let result = points
                .iter()
                .zip(bits.iter())
                .map(|(p, b)| {
                    let to_return = p.mul(b.abs() as u64).into_affine();
                    return if *b < 0 { -to_return } else { to_return };
                })
                .sum();

            return Ok(result);
        }
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

    // b_scalar * b_point + <g_bit_vec, g_point_vec> + <h_bit_vec, h_point_vec>
    pub fn bit_pedersen_vector_commitment(
        b_scalar: &ScalarField,
        b_point: &GroupAffine<G1Parameters>,
        g_bit_vec: &Vec<i8>,
        g_point_vec: &Vec<GroupAffine<G1Parameters>>,
        h_bit_vec: &Vec<i8>,
        h_point_vec: &Vec<GroupAffine<G1Parameters>>,
    ) -> Result<GroupAffine<G1Parameters>, &'static str> {
        let first_inner_product = Self::bit_inner_product(g_point_vec, g_bit_vec);
        let second_inner_product = Self::bit_inner_product(h_point_vec, h_bit_vec);
        if (first_inner_product.is_err() || second_inner_product.is_err()) {
            return Err("Inner product error!");
        } else {
            return Ok(b_point.mul(b_scalar.into_repr()).into_affine()
                + first_inner_product.unwrap()
                + second_inner_product.unwrap());
        }
    }

    pub fn pedersen_test(balance: usize, amounts: &Vec<usize>) {
        let mut rng = ark_std::rand::thread_rng();

        let alpha = Self::get_n_random_scalars(1, &mut rng)[0];
        let rho = Self::get_n_random_scalars(1, &mut rng)[0];

        let a_L = Self::get_a_L(balance, amounts);
        let a_R = Self::get_a_R(&a_L);

        let s_L = Self::get_n_random_scalars(Self::get_n_by_m(amounts.len() + 1), &mut rng);
        let s_R = Self::get_n_random_scalars(Self::get_n_by_m(amounts.len() + 1), &mut rng);

        let g_vec = Self::get_n_generators_berkeley(Self::get_n_by_m(amounts.len() + 1), &mut rng);
        let h_vec = Self::get_n_generators_berkeley(Self::get_n_by_m(amounts.len() + 1), &mut rng);

        let h = Self::get_n_random_points(1, &mut rng)[0];

        let A_commitment =
            Self::bit_pedersen_vector_commitment(&alpha, &h, &a_L, &g_vec, &a_R, &h_vec);

        let S_commitment = Self::pedersen_vector_commitment(&rho, &h, &s_L, &g_vec, &s_R, &h_vec);

        println!(
            "A commitment {:?} - on curve {}",
            A_commitment,
            A_commitment.unwrap().is_on_curve()
        );
        println!(
            "S commitment {:?} - on curve {}",
            S_commitment,
            S_commitment.unwrap().is_on_curve()
        );
    }

    pub fn get_n_by_m(m: usize) -> usize {
        return (usize::BITS as usize) * m;
    }

    pub fn get_n() -> usize {
        return usize::BITS as usize;
    }

    pub fn number_to_bits(number: usize) -> Vec<i8> {
        let mut bits = Vec::<i8>::with_capacity(Self::get_n());
        let bytes = number.to_be_bytes();
        let mut reader = BitReader::new(&bytes);
        while reader.remaining() > 0 {
            bits.push(if reader.read_bool().unwrap() { 1 } else { 0 });
        }
        bits.reverse();
        return bits;
    }

    pub fn get_a_L(balance: usize, amounts: &Vec<usize>) -> Vec<i8> {
        let mut bits = Vec::<i8>::with_capacity(Self::get_n_by_m(amounts.len() + 1));
        Self::number_to_bits(balance)
            .iter()
            .for_each(|bit| bits.push(*bit));

        amounts
            .iter()
            .map(|amount| Self::number_to_bits(*amount))
            .for_each(|bit_array| {
                bit_array.iter().for_each(|bit| bits.push(*bit));
            });

        return bits;
    }

    pub fn get_a_R(a_L: &Vec<i8>) -> Vec<i8> {
        return a_L.iter().map(|bit| bit - 1).collect();
    }

    pub fn test_number_to_bits() {
        let test_number: usize = 42;
        let mut test_number_bits: Vec<i8> = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            1, 0, 1, 0, 1, 0,
        ]
        .to_vec();

        test_number_bits.reverse();
        let resulting_number_bits: Vec<i8> = Self::number_to_bits(test_number);

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

        let result_a_L: Vec<i8> = Self::get_a_L(test_balance, &test_amounts);

        assert_eq!(result_a_L, test_a_L);
    }

    pub fn test_get_a_R() {
        let test_a_L: Vec<i8> = [1, 0, 1, 1, 0, 0, 0, 0, 1].to_vec();
        let test_a_R: Vec<i8> = [0, -1, 0, 0, -1, -1, -1, -1, 0].to_vec();
        let result_a_R: Vec<i8> = Self::get_a_R(&test_a_L);

        assert_eq!(result_a_R, test_a_R);
    }

    pub fn test_bit_inner_product() {
        let mut rng = ark_std::rand::thread_rng();
        let test_points: Vec<GroupAffine<G1Parameters>> =
            Self::get_n_generators_berkeley(2, &mut rng);

        let test_bits_one: Vec<i8> = [1, 1].to_vec();
        let test_bits_two: Vec<i8> = [1, 0].to_vec();
        let test_bits_three: Vec<i8> = [0, 1].to_vec();
        let test_bits_four: Vec<i8> = [0, 0].to_vec();

        let test_bits_minus_one: Vec<i8> = [-1, -1].to_vec();
        let test_bits_minus_two: Vec<i8> = [-1, 0].to_vec();
        let test_bits_minus_three: Vec<i8> = [0, -1].to_vec();

        let test_bits_mix_one: Vec<i8> = [1, -1].to_vec();
        let test_bits_mix_two: Vec<i8> = [-1, 1].to_vec();

        let result_inner_product_one: GroupAffine<G1Parameters> =
            Self::bit_inner_product(&test_points, &test_bits_one).unwrap();
        assert_eq!(result_inner_product_one, test_points[0] + test_points[1]);

        let result_inner_product_two: GroupAffine<G1Parameters> =
            Self::bit_inner_product(&test_points, &test_bits_two).unwrap();
        assert_eq!(
            result_inner_product_two,
            test_points[0] + GroupAffine::zero()
        );

        let result_inner_product_three: GroupAffine<G1Parameters> =
            Self::bit_inner_product(&test_points, &test_bits_three).unwrap();
        assert_eq!(
            result_inner_product_three,
            GroupAffine::zero() + test_points[1]
        );

        let result_inner_product_four: GroupAffine<G1Parameters> =
            Self::bit_inner_product(&test_points, &test_bits_four).unwrap();
        assert_eq!(
            result_inner_product_four,
            GroupAffine::zero() + GroupAffine::zero()
        );

        let result_inner_product_minus_one: GroupAffine<G1Parameters> =
            Self::bit_inner_product(&test_points, &test_bits_minus_one).unwrap();
        assert_eq!(
            result_inner_product_minus_one,
            -test_points[0] + -test_points[1]
        );

        let result_inner_product_minus_two: GroupAffine<G1Parameters> =
            Self::bit_inner_product(&test_points, &test_bits_minus_two).unwrap();
        assert_eq!(
            result_inner_product_minus_two,
            -test_points[0] + GroupAffine::zero()
        );

        let result_inner_product_minus_three: GroupAffine<G1Parameters> =
            Self::bit_inner_product(&test_points, &test_bits_minus_three).unwrap();
        assert_eq!(
            result_inner_product_minus_three,
            GroupAffine::zero() + -test_points[1]
        );

        let result_inner_product_mix_one: GroupAffine<G1Parameters> =
            Self::bit_inner_product(&test_points, &test_bits_mix_one).unwrap();
        assert_eq!(
            result_inner_product_mix_one,
            test_points[0] + -test_points[1]
        );

        let result_inner_product_mix_two: GroupAffine<G1Parameters> =
            Self::bit_inner_product(&test_points, &test_bits_mix_two).unwrap();
        assert_eq!(
            result_inner_product_mix_two,
            -test_points[0] + test_points[1]
        );
    }
}
