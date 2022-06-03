use ark_bn254::g1::{G1_GENERATOR_X, G1_GENERATOR_Y};
use ark_bn254::{Fr as ScalarField, G1Affine as G1Point, G1Projective};
use ark_crypto_primitives::commitment::pedersen::Window;
use ark_crypto_primitives::crh::pedersen::CRH;
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
pub struct ProofUtils;

impl ProofUtils {
    // Berkeley solution
    pub fn get_n_generators_berkeley<R: Rng>(
        number_of_generators: usize,
        rng: &mut R,
    ) -> Vec<G1Point> {
        let gens: Vec<G1Point> =
            CRH::<G1Projective, MockWindow>::generator_powers(number_of_generators, rng)
                .iter()
                .map(|p| p.into_affine())
                .collect::<Vec<G1Point>>();
        return gens;
    }

    pub fn get_n_random_points<R: Rng>(number_of_points: usize, rng: &mut R) -> Vec<G1Point> {
        let mut points: Vec<G1Point> = Vec::<G1Point>::with_capacity(number_of_points);
        for _ in 0..number_of_points {
            points.push(G1Projective::rand(rng).into_affine());
        }
        return points;
    }

    pub fn get_n_random_scalars<R: Rng>(number_of_points: usize, rng: &mut R) -> Vec<ScalarField> {
        let mut scalars: Vec<ScalarField> = Vec::<ScalarField>::with_capacity(number_of_points);
        for _ in 0..number_of_points {
            scalars.push(ScalarField::rand(rng));
        }
        return scalars;
    }

    pub fn get_n_random_scalars_not_zero<R: Rng>(
        number_of_points: usize,
        rng: &mut R,
    ) -> Vec<ScalarField> {
        let mut scalars: Vec<ScalarField> = Vec::<ScalarField>::with_capacity(number_of_points);
        for _ in 0..number_of_points {
            let mut to_push: ScalarField = ScalarField::rand(rng);
            while to_push == ScalarField::zero() {
                to_push = ScalarField::rand(rng);
            }
            scalars.push(to_push);
        }
        return scalars;
    }

    pub fn get_curve_generator() -> G1Point {
        return G1Point::new(G1_GENERATOR_X, G1_GENERATOR_Y, false);
    }

    pub fn inner_product(
        points: &Vec<G1Point>,
        scalars: &Vec<ScalarField>,
    ) -> Result<G1Point, &'static str> {
        if points.len() != scalars.len() {
            return Err("Different lengths! Error!");
        }

        let result: G1Point = points
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
        b_point: &G1Point,
        g_scalar_vec: &Vec<ScalarField>,
        g_point_vec: &Vec<G1Point>,
        h_scalar_vec: &Vec<ScalarField>,
        h_point_vec: &Vec<G1Point>,
    ) -> Result<G1Point, &'static str> {
        let first_inner_product = Self::inner_product(g_point_vec, g_scalar_vec);
        let second_inner_product = Self::inner_product(h_point_vec, h_scalar_vec);
        if first_inner_product.is_err() || second_inner_product.is_err() {
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
        let bits: Vec<u8> = (0..Self::get_n())
            .map(|i| (((number >> i) & 1) as u8))
            .collect();
        return bits;
    }

    pub fn get_a_l(balance: usize, amounts: &Vec<usize>) -> Vec<ScalarField> {
        let mut bits: Vec<u8> = Vec::<u8>::with_capacity(Self::get_n_by_m(amounts.len() + 1));
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

    pub fn get_a_r(a_l: &Vec<ScalarField>) -> Vec<ScalarField> {
        return a_l.iter().map(|bit| *bit - ScalarField::one()).collect();
    }

    /*pub fn l_poly(a_L: &Vec<i8>, z: ScalarField, s_L: Vec<ScalarField>) {
        if a_L.len() != s_L.len() {
            todo!()
        }

        // a_L.iter().map(|bit| *bit - z.into_repr())
    }*/
}
