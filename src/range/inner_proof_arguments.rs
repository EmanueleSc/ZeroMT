use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};

pub struct InnerProofArguments {
    g_vec: Vec<G1Point>,
    h_first_vec: Vec<G1Point>,
    phu: G1Point,
    t_hat: ScalarField,
    l: Vec<ScalarField>,
    r: Vec<ScalarField>,
}

impl InnerProofArguments {
    pub fn new(
        g_vec: Vec<G1Point>,
        h_first_vec: Vec<G1Point>,
        phu: G1Point,
        t_hat: ScalarField,
        l: Vec<ScalarField>,
        r: Vec<ScalarField>,
    ) -> Self {
        InnerProofArguments {
            g_vec,
            h_first_vec,
            phu,
            t_hat,
            l,
            r,
        }
    }

    pub fn get_g_vec(&self) -> &Vec<G1Point> {
        &self.g_vec
    }

    pub fn get_h_first_vec(&self) -> &Vec<G1Point> {
        &self.h_first_vec
    }

    pub fn get_phu(&self) -> &G1Point {
        &self.phu
    }

    pub fn get_t_hat(&self) -> &ScalarField {
        &self.t_hat
    }

    pub fn get_l(&self) -> &Vec<ScalarField> {
        &self.l
    }

    pub fn get_r(&self) -> &Vec<ScalarField> {
        &self.r
    }
}
