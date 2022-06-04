use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
use ark_ff::{Field, One, Zero};
use zeromt::Utils;

fn main() {
    let scalars: Vec<ScalarField> =
        Utils::get_n_random_scalars(5, &mut ark_std::rand::thread_rng());

    println!(
        "{:?}",
        scalars == Utils::product_scalar(&ScalarField::one(), &scalars)
    );
}
