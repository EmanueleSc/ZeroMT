use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
use ark_serialize::*;

#[derive(Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct InnerSigmaProof {
    a: ScalarField,
    b: ScalarField,
    l_vec: Vec<G1Point>,
    r_vec: Vec<G1Point>,
}

impl InnerSigmaProof {
    pub fn new(a: ScalarField, b: ScalarField, l_vec: Vec<G1Point>, r_vec: Vec<G1Point>) -> Self {
        InnerSigmaProof { a, b, l_vec, r_vec }
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
