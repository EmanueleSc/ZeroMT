use std::{marker::PhantomData};
use ark_bn254::{G1Affine, G1Projective};
use ark_crypto_primitives::crh::pedersen::{Window, CRH, bytes_to_bits};
use ark_ec::{ProjectiveCurve};
use ark_std::rand::Rng;

pub struct Bulletproof<W: Window> {
    window: PhantomData<W>,
}

impl <W: Window> Bulletproof <W> {
    /*pub fn get_generators_matrix<R: Rng> (
        rng: &mut R,
    ) -> Vec<Vec<G1Affine>> {
        let vec = CRH::<G1Projective, W>::create_generators(rng);        
        let mut vec_aff: Vec<Vec<G1Affine>> = Vec::new();

        for vec_proj in vec.iter() {
            let mut va: Vec<G1Affine> = Vec::new();
            for point_proj in vec_proj.iter() {
                va.push(point_proj.into_affine());
            }
            vec_aff.push(va);
        }
        vec_aff
    }*/

    pub fn get_generators<R: Rng> (
        rng: &mut R,
    ) -> Vec<G1Affine> {
        let generators = CRH::<G1Projective, W>::generator_powers(W::WINDOW_SIZE, rng)
            .iter()
            .map(|p| p.into_affine())
            .collect();
        generators
    }

    pub fn get_a_L(balance: usize, amounts: &Vec<usize>) -> Vec<i8> {
        let dim = W::WINDOW_SIZE * W::NUM_WINDOWS;
        let mut a_L = Vec::<i8>::with_capacity(dim + 1);

        a_L.extend_from_slice(&Self::to_le_bits(balance));

        amounts
            .iter()
            .for_each(|a| a_L.extend_from_slice(&Self::to_le_bits(*a)));
        a_L
    }

    pub fn to_le_bits(n: usize) -> Vec<i8> {
        let mut bits = Vec::<bool>::with_capacity(W::WINDOW_SIZE);
        let bytes = n.to_le_bytes();
        bits = bytes_to_bits(&bytes);
        bits.iter().map(|b| if *b { 1 } else { 0 }).collect()
    }
}

// TESTS
#[derive(Clone)]
struct MockBulletWindow;

impl Window for MockBulletWindow {
    const WINDOW_SIZE: usize = 64; // n
    const NUM_WINDOWS: usize = 1; // m
}

pub fn generators_test() {
    let mut rng = &mut ark_std::test_rng();
    let gens = Bulletproof::<MockBulletWindow>::get_generators(&mut rng);
    println!("{:?}", gens);
    println!();
    println!("VECTOR LENGTH {}", gens.len());
    println!();
    println!("IS ON CURVE? {}", gens[0].is_on_curve());
}

pub fn tests() {
    let bits = Bulletproof::<MockBulletWindow>::to_le_bits(3);
    println!("{:?}", bits);

    let a_L = Bulletproof::<MockBulletWindow>::get_a_L(3, &vec![3, 1]);
    println!("{:?}", a_L);
    println!("{:?}", a_L.len());
}