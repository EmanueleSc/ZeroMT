use ark_bn254::g1::{G1_GENERATOR_X, G1_GENERATOR_Y};
use ark_bn254::{Fr as ScalarField, G1Affine as G1Point, G1Projective};
use ark_crypto_primitives::commitment::pedersen::Window;
use ark_crypto_primitives::crh::pedersen::CRH;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, One, PrimeField, Zero};
use ark_std::UniformRand;
use rand::Rng;
use std::io::Error;

use crate::bulletproofs::poly_coefficients::PolyCoefficients;
use crate::bulletproofs::poly_vector::PolyVector;
use crate::errors::utils_error::throw;
use crate::UtilsError;

#[derive(Clone)]
struct MockWindow;

impl Window for MockWindow {
    const WINDOW_SIZE: usize = 1;
    const NUM_WINDOWS: usize = 1;
}
pub struct Utils;

impl Utils {
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

    pub fn inner_product_point_scalar(
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

    pub fn product_scalar(s: &ScalarField, vec: &Vec<ScalarField>) -> Vec<ScalarField> {
        vec.iter().map(|v: &ScalarField| *v * *s).collect()
    }

    pub fn sum_scalar(s: &ScalarField, vec: &Vec<ScalarField>) -> Vec<ScalarField> {
        vec.iter().map(|v: &ScalarField| *v + *s).collect()
    }

    pub fn subtract_scalar(s: &ScalarField, vec: &Vec<ScalarField>) -> Vec<ScalarField> {
        vec.iter().map(|v: &ScalarField| *v - *s).collect()
    }

    pub fn inner_product_scalar_scalar(
        vec_1: &Vec<ScalarField>,
        vec_2: &Vec<ScalarField>,
    ) -> Result<ScalarField, Error> {
        if vec_1.len() != vec_2.len() {
            return Err(throw(UtilsError::MathError));
        }

        return Ok(Self::hadamard_product_scalar_scalar(vec_1, vec_2)
            .unwrap()
            .iter()
            .sum());
    }

    pub fn hadamard_product_scalar_scalar(
        vec_1: &Vec<ScalarField>,
        vec_2: &Vec<ScalarField>,
    ) -> Result<Vec<ScalarField>, Error> {
        if vec_1.len() != vec_2.len() {
            return Err(throw(UtilsError::MathError));
        }

        return Ok(vec_1
            .iter()
            .zip(vec_2.iter())
            .map(|(s1, s2)| *s1 * *s2)
            .collect());
    }

    pub fn sum_scalar_scalar(
        vec_1: &Vec<ScalarField>,
        vec_2: &Vec<ScalarField>,
    ) -> Result<Vec<ScalarField>, Error> {
        if vec_1.len() != vec_2.len() {
            return Err(throw(UtilsError::MathError));
        }

        return Ok(vec_1
            .iter()
            .zip(vec_2.iter())
            .map(|(s1, s2)| *s1 + *s2)
            .collect());
    }

    /// b_scalar * b_point + <g_scalar_vec, g_point_vec> + <h_scalar_vec, h_point_vec>
    pub fn pedersen_vector_commitment(
        b_scalar: &ScalarField,
        b_point: &G1Point,
        g_scalar_vec: &Vec<ScalarField>,
        g_point_vec: &Vec<G1Point>,
        h_scalar_vec: &Vec<ScalarField>,
        h_point_vec: &Vec<G1Point>,
    ) -> Result<G1Point, &'static str> {
        let first_inner_product = Self::inner_product_point_scalar(g_point_vec, g_scalar_vec);
        let second_inner_product = Self::inner_product_point_scalar(h_point_vec, h_scalar_vec);
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

    pub fn generate_zero_two_zero_vec(m: usize, j: usize) -> Vec<ScalarField> {
        let n = Self::get_n();
        let mut to_return: Vec<ScalarField> = Vec::<ScalarField>::with_capacity(m * n);
        let two: ScalarField = ScalarField::from(2);
        for _ in 0..((j - 1) * n) {
            to_return.push(ScalarField::zero());
        }
        for i in 0..n {
            to_return.push(two.pow([i as u64]));
        }
        for _ in 0..((m - j) * n) {
            to_return.push(ScalarField::zero());
        }

        return to_return;
    }

    pub fn testing_polynomials(
        y: &ScalarField,
        z: &ScalarField,
        a_l: &Vec<ScalarField>,
        s_l: &Vec<ScalarField>,
        a_r: &Vec<ScalarField>,
        s_r: &Vec<ScalarField>,
        m: usize,
    ) {
        let l_vec_left: Vec<ScalarField> = Self::subtract_scalar(z, a_l);

        let l_vec: PolyVector = PolyVector::new(&l_vec_left, s_l);

        let n = Self::get_n();
        let y_vec: Vec<ScalarField> = (0..m * n).map(|i: usize| y.pow([i as u64])).collect();

        let z_vec: Vec<ScalarField> = (1..=m)
            .map(|j: usize| {
                Self::product_scalar(
                    &z.pow([(1 + j) as u64]),
                    &Self::generate_zero_two_zero_vec(m, j),
                )
            })
            .reduce(|accum: Vec<ScalarField>, item: Vec<ScalarField>| {
                Self::sum_scalar_scalar(&accum, &item).unwrap()
            })
            .unwrap();

        let r_vec_left_hadamard: Vec<ScalarField> =
            Self::hadamard_product_scalar_scalar(&y_vec, &Self::subtract_scalar(z, a_r)).unwrap();

        let r_vec_left: Vec<ScalarField> =
            Self::sum_scalar_scalar(&r_vec_left_hadamard, &z_vec).unwrap();
        let r_vec_right: Vec<ScalarField> =
            Self::hadamard_product_scalar_scalar(&y_vec, &s_r).unwrap();
        let r_vec: PolyVector = PolyVector::new(&r_vec_left, &r_vec_right);

        let t_vec: PolyCoefficients = PolyCoefficients::new(&l_vec, &r_vec);
    }
}
