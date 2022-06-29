use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};

use ark_serialize::*;

#[derive(Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct SigmaSKProof {
    a_y: G1Point,
    s_sk: ScalarField,
}

impl SigmaSKProof {
    pub fn new(a_y: G1Point, s_sk: ScalarField) -> Self {
        SigmaSKProof { a_y, s_sk }
    }

    pub fn get_a_y(&self) -> &G1Point {
        &self.a_y
    }

    pub fn get_s_sk(&self) -> &ScalarField {
        &self.s_sk
    }
}
