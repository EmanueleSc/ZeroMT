use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
use ark_ff::{Field, One, Zero};
use zeromt::Utils;

fn main() {
    println!("{:?}", ScalarField::one());
    let two = ScalarField::from(2);
    println!("{:?}", two);

    println!("{:?}", two.pow([0]));
    println!("{:?}", two);
    println!("{:?}", two.pow([1]));
    println!("{:?}", two);
    println!("{:?}", two.pow([2]));
    println!("{:?}", two * two);
}
