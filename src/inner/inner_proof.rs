use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};

#[derive(Debug)]
pub struct Proof {
    a: ScalarField,
    b: ScalarField,
    l_vec: Vec<G1Point>,
    r_vec: Vec<G1Point>,
}

impl Proof {
    pub fn new(a: ScalarField, b: ScalarField, l_vec: Vec<G1Point>, r_vec: Vec<G1Point>) -> Self {
        Proof { a, b, l_vec, r_vec }
    }

    pub fn get_a(&self) -> &ScalarField {
        return &self.a;
    }

    pub fn get_b(&self) -> &ScalarField {
        return &self.b;
    }

    pub fn get_l_vec(&self) -> &Vec<G1Point> {
        return &self.l_vec;
    }

    pub fn get_r_vec(&self) -> &Vec<G1Point> {
        return &self.r_vec;
    }
}
