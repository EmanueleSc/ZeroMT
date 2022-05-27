mod transcript;
mod prover;
mod verifier;
mod custom_errors;
mod zeromt;

use ark_crypto_primitives::commitment::pedersen::Window;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::PrimeField;
use ark_std::{rand, UniformRand};
use ark_bn254::g1::{G1_GENERATOR_X, G1_GENERATOR_Y};
use ark_bn254::{G1Affine as G1, Fr as ScalarField};

use crate::zeromt::BulletGenerators;

/*
Schnorr Sigma-protocol for DL relation:

Public inputs: G (group generator) and H = w * G
Private inputs: w (scalar value)

Prover:
    rand 'r' from group
    computes A = r * G
    sends 'A' to the verifier

Verifer:
    rand challange 'e' from group 
    sends 'e' to the prover

Prover:
    computes z = (we + r) mod |group|
    sends 'z' to the verifier

Verifier:
    cheks if A + (e * H) = z * G

TRANSCRIPT = (A, e, z)
*/

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct BWindow;

impl Window for BWindow {
    const WINDOW_SIZE: usize = 32; // n bit len
    const NUM_WINDOWS: usize = 1; // m values
}

fn main() {
    println!("Hello, Proof System!");

    //let mut rng = rand::thread_rng();
    let mut rng = &mut ark_std::test_rng();
    let vec = BulletGenerators::<BWindow>::get_generators(&mut rng);
    println!("{:?}", vec);
    println!();
    println!("VECTOR LENGTH {}", vec[0].len());
    println!();
    println!("IS ON CURVE? {}", vec[0][0].is_on_curve());

    /*let mut rng = rand::thread_rng();

    // Prover inputs 
    let G = G1::new(G1_GENERATOR_X, G1_GENERATOR_Y, false);
    let w = ScalarField::from(42u64);
    let H = G.mul(w.into_repr()).into_affine();

    println!("------ PROVER INPUTS ------");
    println!("Generator G: {:?} - on curve: {}", G, G.is_on_curve());
    println!("Witness w: {:?}", w);
    println!("Group elem H: {:?} - on curve: {}", H, H.is_on_curve());

    // Prover computes:
    let r = ScalarField::rand(&mut rng);
    let A = G.mul(r.into_repr()).into_affine();

    println!("-> PROVER computes:");
    println!("r {:?}", r);
    println!("Group elem A {:?} - on curve {}", A, A.is_on_curve());

    // Verifier computes:
    let e = ScalarField::rand(&mut rng);

    println!("-> VERIFIER challange:");
    println!("e {:?}", e);

    // Prover computes:
    let z = (w * e) + r;
    
    println!("-> PROVER computes:");
    println!("z {:?}", z);

    // Verifier checks:
    let left_eq = (H.mul(e.into_repr()).into_affine()) + A;
    let right_eq = G.mul(z.into_repr()).into_affine();

    println!("-> VERIFIER checks:");
    println!("left_eq: {:?} - on curve: {}", left_eq, left_eq.is_on_curve());
    println!("right_eq: {:?} - on curve: {}", right_eq, right_eq.is_on_curve());

    assert_eq!(left_eq, right_eq);*/

}
