use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};

use ark_serialize::*;

#[derive(Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct SigmaABProof {
    a_ab: G1Point,
    s_sk: ScalarField,
    s_ab: ScalarField,
}

impl SigmaABProof {
    pub fn new(a_ab: G1Point, s_sk: ScalarField, s_ab: ScalarField) -> Self {
        SigmaABProof { a_ab, s_sk, s_ab }
    }

    pub fn get_a_ab(&self) -> &G1Point {
        &self.a_ab
    }

    pub fn get_s_sk(&self) -> &ScalarField {
        &self.s_sk
    }

    pub fn get_s_ab(&self) -> &ScalarField {
        &self.s_ab
    }
}
