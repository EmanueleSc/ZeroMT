mod proof_system_utils;
mod prover;
mod schnorr_proof;
mod transcript;
mod verifier;

use ark_crypto_primitives::crh::pedersen::{Window, CRH};
use ark_ec::short_weierstrass_jacobian::GroupAffine;

use prover::Prover;
use rand::prelude::ThreadRng;
use verifier::Verifier;

use ark_bn254::g1::{G1_GENERATOR_X, G1_GENERATOR_Y};
use ark_bn254::{g1::Parameters, Fr as ScalarField, G1Affine, G1Projective};

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::PrimeField;
use merlin::Transcript;

use proof_system_utils::ProofSystemUtils;

fn main() {
    /* let mut prover_transcript = Transcript::new(b"SchnorrExample");
    let mut verifier_transcript = Transcript::new(b"SchnorrExample");
    let w_int = 42i64;
    let w = ScalarField::from(w_int);
    println!("witness w {:?}", w);

    let g = G1Affine::new(G1_GENERATOR_X, G1_GENERATOR_Y, false);
    println!("generator g {:?}  - on curve {}", g, g.is_on_curve());

    let h = g.mul(w.into_repr()).into_affine();
    println!("h {:?} - on curve {}", h, h.is_on_curve());

    let mut schnorr_prover = Prover::new(&mut prover_transcript, &g, &h, &w);

    let proof = schnorr_prover.generate_proof();
    println!("{:?}", proof);

    let mut schnorr_verifier = Verifier::new(&mut verifier_transcript, &g, &h);
    let result = schnorr_verifier.verify_proof(&proof);
    println!("{:?}", result);*/
    let generator = ProofSystemUtils::get_generator_hash(4);

    println!("{:?}", generator);
}
