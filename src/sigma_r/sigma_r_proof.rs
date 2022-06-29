use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};

use ark_serialize::*;

#[derive(Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct SigmaRProof {
    a_d: G1Point,
    s_r: ScalarField,
}

impl SigmaRProof {
    pub fn new(a_d: G1Point, s_r: ScalarField) -> Self {
        SigmaRProof { a_d, s_r }
    }

    pub fn get_a_d(&self) -> &G1Point {
        &self.a_d
    }

    pub fn get_s_r(&self) -> &ScalarField {
        &self.s_r
    }
}
