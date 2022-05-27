use std::marker::PhantomData;

use ark_bn254::{G1Affine, G1Projective};
use ark_crypto_primitives::crh::pedersen::{Window, CRH};
use ark_ec::ProjectiveCurve;
use ark_std::rand::Rng;

pub struct BulletGenerators<W: Window> {
    window: PhantomData<W>,
    //generators: Vec<Vec<G1Affine>>,
}

impl <W: Window> BulletGenerators <W> {
    pub fn get_generators<R: Rng> (rng: &mut R) -> Vec<Vec<G1Affine>> {
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
    }
}