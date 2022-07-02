use ark_bn254::g1::{G1_GENERATOR_X, G1_GENERATOR_Y};
use ark_bn254::{Fr as ScalarField, G1Affine as G1Point, G1Projective};
use ark_crypto_primitives::commitment::pedersen::Window;
use ark_crypto_primitives::crh::pedersen::CRH;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, One, PrimeField, Zero};
use ark_std::UniformRand;
use rand::Rng;
use std::io::Error;

use crate::errors::utils_error::throw;
use crate::UtilsError;

pub struct ElGamal;

impl ElGamal {
    pub fn elgamal_encrypt(
        amount: usize,
        pub_key: &G1Point,
        g: &G1Point,
        r: &ScalarField,
    ) -> (G1Point, G1Point) {
        let to_encrypt: ScalarField = ScalarField::from(amount as i128);
        let c: G1Point =
            g.mul(to_encrypt.into_repr()).into_affine() + pub_key.mul(r.into_repr()).into_affine();

        let d: G1Point = g.mul(r.into_repr()).into_affine();

        (c, d)
    }

    pub fn elgamal_d(g: &G1Point, r: &ScalarField) -> G1Point {
        g.mul(r.into_repr()).into_affine()
    }

    pub fn elgamal_calculate_pub_key(priv_key: &ScalarField, g: &G1Point) -> G1Point {
        g.mul(priv_key.into_repr()).into_affine()
    }
}
