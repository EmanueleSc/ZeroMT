use ark_bn254::g1::{G1_GENERATOR_X, G1_GENERATOR_Y};
use ark_bn254::{
    g1::Parameters as G1Parameters, Fq as BaseField, Fr as ScalarField, G1Affine, G1Projective,
};
use ark_crypto_primitives::commitment::pedersen::Window;
use ark_crypto_primitives::crh::pedersen::CRH;
use ark_ec::short_weierstrass_jacobian::GroupAffine;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{PrimeField, ToBytes};
use ark_std::UniformRand;
use rand::Rng;
use std::io::Error;

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
                + Self::inner_product(g_point_vec, g_scalar_vec).unwrap()
                + Self::inner_product(h_point_vec, h_scalar_vec).unwrap());
        }
    }

    pub fn pedersen_test() {
        let mut rng = ark_std::rand::thread_rng();
        let n_elements = 5;
        let alpha = Self::get_n_random_scalars(1, &mut rng)[0];
        let rho = Self::get_n_random_scalars(1, &mut rng)[0];

        let a_L = Self::get_n_random_scalars(n_elements, &mut rng);
        let a_R = Self::get_n_random_scalars(n_elements, &mut rng);
        let s_L = Self::get_n_random_scalars(n_elements, &mut rng);
        let s_R = Self::get_n_random_scalars(n_elements, &mut rng);

        let g_vec = Self::get_n_generators_berkeley(n_elements, &mut rng);
        let h_vec = Self::get_n_generators_berkeley(n_elements, &mut rng);

        let h = Self::get_n_random_points(1, &mut rng)[0];

        let A_commitment = Self::pedersen_vector_commitment(&alpha, &h, &a_L, &g_vec, &a_R, &h_vec);

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
}
