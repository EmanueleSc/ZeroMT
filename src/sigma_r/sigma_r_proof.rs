use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};

#[derive(Debug)]
pub struct Proof {
    a_d: G1Point,
    s_r: ScalarField,
}

impl Proof {
    pub fn new(a_d: G1Point, s_r: ScalarField) -> Self {
        Proof { a_d, s_r }
    }

    pub fn get_a_d(&self) -> &G1Point {
        &self.a_d
    }

    pub fn get_s_r(&self) -> &ScalarField {
        &self.s_r
    }
}
