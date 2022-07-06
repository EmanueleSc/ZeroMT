use ark_bn254::g1::{G1_GENERATOR_X, G1_GENERATOR_Y};
use ark_bn254::{Fr as ScalarField, G1Affine as G1Point, G1Projective};
use ark_crypto_primitives::commitment::pedersen::Window;
use ark_crypto_primitives::crh::pedersen::CRH;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, PrimeField, Zero};
use ark_std::UniformRand;
use rand::Rng;
use std::io::Error;

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
    /// Berkeley solution
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

    /// Each scalar is multiplied to each point. The sum of all results is then made.
    pub fn inner_product_point_scalar(
        points: &Vec<G1Point>,
        scalars: &Vec<ScalarField>,
    ) -> Result<G1Point, Error> {
        if points.len() != scalars.len() {
            return Err(throw(UtilsError::MathError));
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

    /// The scalar is multiplied to each scalar of the vector.
    pub fn product_scalar(s: &ScalarField, vec: &Vec<ScalarField>) -> Vec<ScalarField> {
        vec.iter().map(|v: &ScalarField| *v * *s).collect()
    }

    /// The scalar is multiplied to each point of the vector.
    pub fn product_scalar_point(s: &ScalarField, vec: &Vec<G1Point>) -> Vec<G1Point> {
        vec.iter()
            .map(|v: &G1Point| v.mul(s.into_repr()).into_affine())
            .collect()
    }

    /// The scalar is add to each scalar of the vector.
    pub fn sum_scalar(s: &ScalarField, vec: &Vec<ScalarField>) -> Vec<ScalarField> {
        vec.iter().map(|v: &ScalarField| *v + *s).collect()
    }

    /// The scalar is subtracted from each scalar of the vector.
    pub fn subtract_scalar(s: &ScalarField, vec: &Vec<ScalarField>) -> Vec<ScalarField> {
        vec.iter().map(|v: &ScalarField| *v - *s).collect()
    }

    /// Inner product betweeen scalars vectors
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

    pub fn generate_scalar_exp_vector(n: usize, s: &ScalarField) -> Vec<ScalarField> {
        (0..n).map(|i: usize| s.pow([i as u64])).collect()
    }

    /// Hadamard product betweeen scalars vectors
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
            .map(|(s1, s2): (&ScalarField, &ScalarField)| *s1 * *s2)
            .collect());
    }

    /// Sum betweeen point vectors
    pub fn sum_point_point(
        vec_1: &Vec<G1Point>,
        vec_2: &Vec<G1Point>,
    ) -> Result<Vec<G1Point>, Error> {
        if vec_1.len() != vec_2.len() {
            return Err(throw(UtilsError::MathError));
        }

        return Ok(vec_1
            .iter()
            .zip(vec_2.iter())
            .map(|(p1, p2): (&G1Point, &G1Point)| *p1 + *p2)
            .collect());
    }

    /// Sum betweeen scalars vectors
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
            .map(|(s1, s2): (&ScalarField, &ScalarField)| *s1 + *s2)
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
    ) -> Result<G1Point, Error> {
        let first_inner_product = Self::inner_product_point_scalar(g_point_vec, g_scalar_vec);
        let second_inner_product = Self::inner_product_point_scalar(h_point_vec, h_scalar_vec);
        if first_inner_product.is_err() || second_inner_product.is_err() {
            return Err(throw(UtilsError::MathError));
        } else {
            return Ok(b_point.mul(b_scalar.into_repr()).into_affine()
                + first_inner_product.unwrap()
                + second_inner_product.unwrap());
        }
    }

    /// g_scalar * g_point + h_scalar * h_point
    pub fn pedersen_commitment(
        g_scalar: &ScalarField,
        g_point: &G1Point,
        h_scalar: &ScalarField,
        h_point: &G1Point,
    ) -> G1Point {
        g_point.mul(g_scalar.into_repr()).into_affine()
            + h_point.mul(h_scalar.into_repr()).into_affine()
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

    pub fn get_mock_balances<R: Rng>(m: usize, rng: &mut R) -> (usize, Vec<usize>, usize) {
        let total_balance: usize = usize::MAX / 2;
        let mut amounts: Vec<usize> = [].to_vec();
        let mut balance_remaining: usize = total_balance;
        for _ in 1..m {
            let to_add = rng.gen_range(1..100);
            amounts.push(to_add);
            balance_remaining = total_balance - amounts.iter().sum::<usize>();
        }

        (total_balance, amounts, balance_remaining)
    }
}
