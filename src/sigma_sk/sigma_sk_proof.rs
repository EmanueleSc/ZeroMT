use ark_bn254::{G1Affine as G1Point, Fr as ScalarField};

pub struct SigmaSkProof {
    a_y: G1Point,
    s_sk: ScalarField,
}

impl SigmaSkProof {
    pub fn new(a_y: G1Point, s_sk: ScalarField) -> Self {
        SigmaSkProof { a_y, s_sk }
    }

    pub fn get_a_y(&self) -> &G1Point {
        &self.a_y
    }

    pub fn get_s_sk(&self) -> &ScalarField {
        &self.s_sk
    }
}