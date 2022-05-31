use ark_bn254::g1::{G1_GENERATOR_X, G1_GENERATOR_Y};
use ark_bn254::{
    g1::Parameters as G1Parameters, Fq as BaseField, Fr as ScalarField, G1Affine, G1Projective,
};
use ark_crypto_primitives::commitment::pedersen::Window;
use ark_crypto_primitives::crh::pedersen::CRH;
use ark_ec::short_weierstrass_jacobian::GroupAffine;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{BigInteger, BigInteger256, PrimeField, ToBytes, Zero};
use ark_std::UniformRand;
use bitreader::BitReader;
use rand::Rng;
use std::io::Error;
use std::result;

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
                    return match b {
                        1 => *p,
                        -1 => -*p,
                        0 => GroupAffine::zero(),
                        _ => GroupAffine::zero(),
                    };
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
}
