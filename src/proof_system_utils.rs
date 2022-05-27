use ark_crypto_primitives::commitment::pedersen::{Commitment, Parameters, Randomness, Window};
use ark_crypto_primitives::crh::pedersen::CRH;
use ark_crypto_primitives::{commitment, CommitmentScheme};

use ark_ec::short_weierstrass_jacobian::GroupAffine;
use ark_std::UniformRand;
use rand::prelude::ThreadRng;

use ark_bn254::g1::{G1_GENERATOR_X, G1_GENERATOR_Y};
use ark_bn254::{g1::Parameters as G1Parameters, Fr as ScalarField, G1Affine, G1Projective};

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::PrimeField;
use merlin::Transcript;

#[derive(Clone)]
struct MockWindow;

impl Window for MockWindow {
    const WINDOW_SIZE: usize = 1; // n
    const NUM_WINDOWS: usize = 1;
}
pub struct ProofSystemUtils;

impl ProofSystemUtils {
    pub fn get_n_generators(number_of_generators: usize) -> Vec<GroupAffine<G1Parameters>> {
        let mut rng: ThreadRng = ark_std::rand::thread_rng();
        let gens =
            CRH::<G1Projective, MockWindow>::generator_powers(number_of_generators, &mut rng)
                .iter()
                .map(|p| p.into_affine())
                .collect::<Vec<GroupAffine<G1Parameters>>>();
        return gens;
    }

    pub fn get_n_random_points(number_of_points: usize) -> Vec<GroupAffine<G1Parameters>> {
        let mut rng: ThreadRng = ark_std::rand::thread_rng();
        let mut points = Vec::<GroupAffine<G1Parameters>>::with_capacity(number_of_points);
        for _ in 0..number_of_points {
            points.push(G1Projective::rand(&mut rng).into_affine());
        }
        return points;
    }

    /// ???????????????????
    pub fn pedersen_commit_test() {
        let mut rng: ThreadRng = ark_std::rand::thread_rng();

        let params = Commitment::<G1Projective, MockWindow>::setup(&mut rng).unwrap();
        let randomness = Randomness::<G1Projective>::rand(&mut rng);

        let result =
            Commitment::<G1Projective, MockWindow>::commit(&params, &[], &randomness).unwrap();
        // ????????????????????????
    }
}
