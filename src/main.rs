mod prover;
mod transcript;
mod verifier;
use std::ops::Mul;

use crate::transcript::TranscriptProtocol;
use prover::Prover;
use verifier::Verifier;

use ark_bn254::g1::{G1_GENERATOR_X, G1_GENERATOR_Y};
use ark_bn254::{Fq as BaseField, Fr as ScalarField, G1Affine, G1Projective};
use ark_ec::models::bn::BnParameters;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, PrimeField};
use ark_std::{One, UniformRand, Zero};
use merlin::Transcript;
use rand::Rng;

fn main() {
    let mut prover_transcript = Transcript::new(b"SchnorrExample");
    let mut verifier_transcript = Transcript::new(b"SchnorrExample");
    let mut rng = ark_std::rand::thread_rng();

    let w_int = 42i64;
    let w = ScalarField::from(w_int);
    println!("witness w {:?}", w);

    let g = G1Affine::new(G1_GENERATOR_X, G1_GENERATOR_Y, false);
    println!("generator g {:?}  - on curve {}", g, g.is_on_curve());

    let h = g.mul(w.into_repr()).into_affine();
    println!("h {:?} - on curve {}", h, h.is_on_curve());

    let schnorr_prover = Prover::new(&mut prover_transcript, &g, &h, &w);
    let schnorr_verifier = Verifier::new(&mut verifier_transcript, &g, &h);

    // Calcoli
    let r = ScalarField::rand(&mut rng);
    let a = g.mul(r.into_repr()).into_affine();
    println!("r {:?}", r);
    println!("a {:?} - on curve {}", a, a.is_on_curve());

    let e = ScalarField::rand(&mut rng);

    let z = (w * e) + r;

    let eh = h.mul(e.into_repr()).into_affine();
    let a_plus_eh = a + eh;
    let zg = g.mul(z.into_repr()).into_affine();
    assert_eq!(a_plus_eh, zg);

    println!(
        "a_plus_eh {:?} - on curve {}",
        a_plus_eh,
        a_plus_eh.is_on_curve()
    );
    println!("zg {:?} - on curve {}", zg, zg.is_on_curve());

    //////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////

    /* use ark_ec::{AffineCurve, ProjectiveCurve};
    use ark_ff::{Field, PrimeField};
    // Use the BN254 curve
    use ark_bn254::{Fr as ScalarField, G1Affine as GAffine, G1Projective as G};
    use ark_std::{One, UniformRand, Zero};

    let mut rng = ark_std::rand::thread_rng();
    // Let's sample uniformly random field elements:

    let a = G::rand(&mut rng);
    let b = G::rand(&mut rng);

    let b_affine = G::rand(&mut rng).into_affine();
    // We can add...
    let c = a + b;
    println!("{:?}", a.into_affine());
    // ... subtract ...
    let d = a - b;
    // ... and double elements.
    assert_eq!(c + d, a.double());
    // We can also negate elements...
    let e = -a;
    assert_eq!(e + a, G::zero());

    // ...and multiply group elements by elements of the corresponding scalar field
    let scalar = ScalarField::rand(&mut rng);

    let e = c.mul(&scalar.into_repr()); // into_repr() converts the scalar into a `BigInteger`.
    let f = e.mul(&scalar.inverse().unwrap().into_repr());
    assert_eq!(f, c);

    // Finally, we can also convert curve points in projective coordinates to affine coordinates.
    let c_aff = c.into_affine();
    // Most group operations are slower in affine coordinates, but adding an affine point
    // to a projective one is slightly more efficient.
    let d = c.add_mixed(&c_aff);
    assert_eq!(d, c.double());

    // This efficiency also translates into more efficient scalar multiplication routines.
    let e_from_aff = c_aff.mul(scalar.into_repr());
    assert_eq!(e, e_from_aff);

    // Finally, while not recommended, users can directly construct group elements
    // from the x and y coordinates. This is useful when implementing algorithms
    // like hash-to-curve.
    let e_affine = e.into_affine();
    let e_x = e_affine.x;
    let e_y = e_affine.y;

    let is_at_infinity = e_affine.is_zero();

    let new_e = GAffine::new(e_x, e_y, is_at_infinity);
    assert_eq!(e_affine, new_e);
    // Users should check that the new point is on the curve and is in the prime-order group:
    assert!(new_e.is_on_curve());
    assert!(new_e.is_in_correct_subgroup_assuming_on_curve());*/
}
