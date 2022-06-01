mod proof_system_utils;
mod schnorr;
mod transcript;

use ark_bn254::{g1::Parameters, Fr as ScalarField, G1Affine, G1Projective};
use schnorr::schnorr_prover::Prover;
use schnorr::schnorr_verifier::Verifier;

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::PrimeField;
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

    ProofSystemUtils::test_number_to_be_bits();
    ProofSystemUtils::test_number_to_be_bits_reversed();
    ProofSystemUtils::test_get_a_L();
    ProofSystemUtils::test_get_a_R();
    ProofSystemUtils::test_bit_inner_product();
}
