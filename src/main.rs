mod proof_system_utils;
mod schnorr;
mod transcript;

use schnorr::schnorr_prover::Prover;
use schnorr::schnorr_verifier::Verifier;

use ark_bn254::{
    g1::Parameters as G1Parameters, Fq as BaseField, Fr as ScalarField, G1Affine, G1Projective,
};
use ark_crypto_primitives::commitment::pedersen::Window;
use ark_crypto_primitives::crh::pedersen::CRH;
use ark_ec::short_weierstrass_jacobian::GroupAffine;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{One, PrimeField, Zero};
use merlin::Transcript;
use proof_system_utils::ProofSystemUtils;

fn main() {
    /* let mut prover_transcript = Transcript::new(b"SchnorrExample");
    let mut verifier_transcript = Transcript::new(b"SchnorrExample");

    let mut rng = ark_std::rand::thread_rng();

    let w = ProofSystemUtils::get_n_random_scalars(1, &mut rng)[0];
    println!("witness w {:?}", w);

    let g = ProofSystemUtils::get_curve_generator();
    println!("generator g {:?}  - on curve {}", g, g.is_on_curve());

    let h = g.mul(w.into_repr()).into_affine();
    println!("h {:?} - on curve {}", h, h.is_on_curve());

    let mut schnorr_prover = Prover::new(&mut prover_transcript, &g, &h, &w);

    let proof = schnorr_prover.generate_proof(&mut rng);
    println!("{:?}", proof);

    let mut schnorr_verifier = Verifier::new(&mut verifier_transcript, &g, &h);
    let result = schnorr_verifier.verify_proof(&proof);
    println!("{:?}", result);*/

    ProofSystemUtils::test_inner_product();
    ProofSystemUtils::test_get_a_L();
    ProofSystemUtils::test_get_a_R();
    ProofSystemUtils::test_number_to_be_bits();
    ProofSystemUtils::test_number_to_be_bits_reversed();
}

pub fn pedersen_test(balance: usize, amounts: &Vec<usize>) {
    let mut rng = ark_std::rand::thread_rng();

    let alpha: ScalarField = ProofSystemUtils::get_n_random_scalars(1, &mut rng)[0];
    let rho: ScalarField = ProofSystemUtils::get_n_random_scalars(1, &mut rng)[0];

    let a_L: Vec<ScalarField> = ProofSystemUtils::get_a_L(balance, amounts);
    let a_R: Vec<ScalarField> = ProofSystemUtils::get_a_R(&a_L);

    let s_L: Vec<ScalarField> = ProofSystemUtils::get_n_random_scalars(
        ProofSystemUtils::get_n_by_m(amounts.len() + 1),
        &mut rng,
    );
    let s_R: Vec<ScalarField> = ProofSystemUtils::get_n_random_scalars(
        ProofSystemUtils::get_n_by_m(amounts.len() + 1),
        &mut rng,
    );

    let g_vec: Vec<GroupAffine<G1Parameters>> = ProofSystemUtils::get_n_generators_berkeley(
        ProofSystemUtils::get_n_by_m(amounts.len() + 1),
        &mut rng,
    );
    let h_vec: Vec<GroupAffine<G1Parameters>> = ProofSystemUtils::get_n_generators_berkeley(
        ProofSystemUtils::get_n_by_m(amounts.len() + 1),
        &mut rng,
    );

    let h = ProofSystemUtils::get_n_random_points(1, &mut rng)[0];

    let A_commitment =
        ProofSystemUtils::pedersen_vector_commitment(&alpha, &h, &a_L, &g_vec, &a_R, &h_vec);

    let S_commitment =
        ProofSystemUtils::pedersen_vector_commitment(&rho, &h, &s_L, &g_vec, &s_R, &h_vec);

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
