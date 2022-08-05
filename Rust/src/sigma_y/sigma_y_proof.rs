use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};

use ark_serialize::*;

#[derive(Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct SigmaYProof {
    a_y_bar: G1Point,
    s_r: ScalarField,
}

impl SigmaYProof {
    pub fn new(a_y_bar: G1Point, s_r: ScalarField) -> Self {
        SigmaYProof { a_y_bar, s_r }
    }

    pub fn get_a_y_bar(&self) -> &G1Point {
        &self.a_y_bar
    }

    pub fn get_s_r(&self) -> &ScalarField {
        &self.s_r
    }
}
