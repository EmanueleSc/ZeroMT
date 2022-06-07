use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};

#[derive(Debug)]
pub struct Proof {
    a_y_bar: G1Point,
    s_r: ScalarField,
}

impl Proof {
    pub fn new(a_y_bar: G1Point, s_r: ScalarField) -> Self {
        Proof { a_y_bar, s_r }
    }

    pub fn get_a_y_bar(&self) -> &G1Point {
        &self.a_y_bar
    }

    pub fn get_s_r(&self) -> &ScalarField {
        &self.s_r
    }
}
