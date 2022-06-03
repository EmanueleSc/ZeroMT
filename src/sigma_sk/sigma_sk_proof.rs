use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};

#[derive(Debug)]
pub struct Proof {
    a_y: G1Point,
    s_sk: ScalarField,
}

impl Proof {
    pub fn new(a_y: G1Point, s_sk: ScalarField) -> Self {
        Proof { a_y, s_sk }
    }

    pub fn get_a_y(&self) -> &G1Point {
        &self.a_y
    }

    pub fn get_s_sk(&self) -> &ScalarField {
        &self.s_sk
    }
}
