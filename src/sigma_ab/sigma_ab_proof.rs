use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};

#[derive(Debug)]
pub struct Proof {
    a_ab: G1Point,
    s_sk: ScalarField,
    s_ab: ScalarField,
}

impl Proof {
    pub fn new(a_ab: G1Point, s_sk: ScalarField, s_ab: ScalarField) -> Self {
        Proof { a_ab, s_sk, s_ab }
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
