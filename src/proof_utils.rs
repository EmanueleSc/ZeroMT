use ark_bn254::{G1Affine, G1Projective};
use ark_ec::{ProjectiveCurve};
use ark_crypto_primitives::crh::pedersen::{Window, CRH};
use ark_std::rand::Rng;

#[derive(Clone)]
struct MockWindow;

impl Window for MockWindow {
    const WINDOW_SIZE: usize = 1;
    const NUM_WINDOWS: usize = 1;
}

pub struct ProofUtils;

impl ProofUtils {

    pub fn get_generators<R: Rng> (
        number_of_generators: usize,
        rng: &mut R,
    ) -> Vec<G1Affine> {
        let generators = CRH::<G1Projective, MockWindow>::generator_powers(number_of_generators, rng)
            .iter()
            .map(|p| p.into_affine())
            .collect();
        generators
    }

}

// OLD STAFF (Consider to transfer to a Bullet module)
/*pub fn get_a_L(balance: usize, amounts: &Vec<usize>) -> Vec<i8> {
    let mut a_L = Vec::<i8>::new();
    a_L.extend_from_slice(&Self::to_le_bits(balance));

    amounts
        .iter()
        .for_each(|a|
            a_L.extend_from_slice(&Self::to_le_bits(*a))
        );
    a_L
}
pub fn to_le_bits(n: usize) -> Vec<i8> {
    let mut bits = Vec::<bool>::with_capacity(W::WINDOW_SIZE);
    let bytes = n.to_le_bytes();
    bits = bytes_to_bits(&bytes);
    bits.iter().map(|b| if *b { 1 } else { 0 }).collect()
}
pub fn tests() {
    let bits = Bulletproof::<MockBulletWindow>::to_le_bits(3);
    println!("{:?}", bits);

    let a_L = Bulletproof::<MockBulletWindow>::get_a_L(3, &vec![3, 1]);
    println!("{:?}", a_L);
    println!("{:?}", a_L.len());
}*/