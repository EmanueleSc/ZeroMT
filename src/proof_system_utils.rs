use std::hash;

use ark_crypto_primitives::commitment::pedersen::{Commitment, Randomness, Window};
use ark_crypto_primitives::crh::pedersen::CRH;
use ark_crypto_primitives::{commitment, CommitmentScheme};

use ark_ec::short_weierstrass_jacobian::GroupAffine;
use ark_std::UniformRand;
use rand::prelude::ThreadRng;

use ark_bn254::g1::{G1_GENERATOR_X, G1_GENERATOR_Y};
use ark_bn254::{
    g1::Parameters as G1Parameters, Fq as BaseField, Fr as ScalarField, G1Affine, G1Projective,
};

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{PrimeField, ToBytes};
use hex_literal::hex;
use merlin::Transcript;
use sha2::{Digest, Sha256};

use std::io::Error;

#[derive(Clone)]
struct MockWindow;

impl Window for MockWindow {
    const WINDOW_SIZE: usize = 1; // n
    const NUM_WINDOWS: usize = 1;
}
pub struct ProofSystemUtils;

impl ProofSystemUtils {
    // Berkeley solution
    pub fn get_n_generators_berkeley(
        number_of_generators: usize,
    ) -> Vec<GroupAffine<G1Parameters>> {
        let mut rng: ThreadRng = ark_std::rand::thread_rng();
        let gens =
            CRH::<G1Projective, MockWindow>::generator_powers(number_of_generators, &mut rng)
                .iter()
                .map(|p| p.into_affine())
                .collect::<Vec<GroupAffine<G1Parameters>>>();
        return gens;
    }

    // Berkeley solution
    pub fn get_n_random_points(number_of_points: usize) -> Vec<GroupAffine<G1Parameters>> {
        let mut rng: ThreadRng = ark_std::rand::thread_rng();
        let mut points = Vec::<GroupAffine<G1Parameters>>::with_capacity(number_of_points);
        for _ in 0..number_of_points {
            points.push(G1Projective::rand(&mut rng).into_affine());
        }
        return points;
    }

    /* pub fn get_n_generators_zeromt(number_of_generators: usize) -> Vec<GroupAffine<G1Parameters>> {
        let mut generators = Vec::with_capacity(number_of_generators);

        for index in 0..number_of_generators {
            generators.push(Self::get_generator_hash(index).unwrap());
        }

        return generators;
    }*/

    pub fn get_generator_hash(index: usize) -> Result<GroupAffine<G1Parameters>, &'static str> {
        let mut hasher = Sha256::new();
        let point = G1Affine::new(G1_GENERATOR_X, G1_GENERATOR_Y, false);
        let mut bytes = Vec::new();
        point.write(&mut bytes);

        hasher.update(bytes);
        hasher.update(index.to_string());

        let hash_result = hasher.finalize();

        println!("Hash result {:?}", hash_result);

        //let x: [u8; 32] = hash_result.as_slice().try_into().expect("Wrong length");

        let x_coord = BaseField::from_be_bytes_mod_order(&hash_result);

        let new_point_from_x = G1Affine::get_point_from_x(x_coord, true);
        if (new_point_from_x.is_some()) {
            println!(
                "Generated point: {:?} - On curve {}",
                new_point_from_x.unwrap(),
                new_point_from_x.unwrap().is_on_curve()
            );
            let to_return: GroupAffine<G1Parameters> = new_point_from_x.unwrap();
            return Ok(to_return);
        } else {
            return Err("Error generating the point");
        }
    }

    pub fn random_point() -> GroupAffine<G1Parameters> {
        return G1Projective::rand(&mut ark_std::rand::thread_rng()).into_affine();
    }

    pub fn random_scalar() -> ScalarField {
        return ScalarField::rand(&mut ark_std::rand::thread_rng());
    }
}
