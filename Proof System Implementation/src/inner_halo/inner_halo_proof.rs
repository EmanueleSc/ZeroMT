use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
use ark_serialize::*;

#[derive(Debug, CanonicalDeserialize, CanonicalSerialize)]
// TODO: MODIFYs
pub struct InnerHaloProof {
    l_vec: Vec<G1Point>,
    r_vec: Vec<G1Point>,
    r: G1Point,              // Schnorr commitment R
    z_one: ScalarField,      // Schnorr
    z_two: ScalarField       // Schnorr
}

impl InnerHaloProof {
    pub fn new(l_vec: Vec<G1Point>, r_vec: Vec<G1Point>, r: G1Point, z_one: ScalarField, z_two: ScalarField) -> Self {
        InnerHaloProof { l_vec, r_vec, r, z_one, z_two }
    }

    pub fn get_l_vec(&self) -> &Vec<G1Point> {
        return &self.l_vec;
    }

    pub fn get_r_vec(&self) -> &Vec<G1Point> {
        return &self.r_vec;
    }

    pub fn get_r(&self) -> &G1Point {
        return &self.r;
    }

    pub fn get_z_one(&self) -> &ScalarField {
        return &self.z_one;
    }

    pub fn get_z_two(&self) -> &ScalarField {
        return &self.z_two;
    }
}
