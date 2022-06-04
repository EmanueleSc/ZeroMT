use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};

#[derive(Debug)]
pub struct Proof {
    a: G1Point,
    s: G1Point,
    t_1: G1Point,
    t_2: G1Point,
}

impl Proof {
    pub fn new(a: G1Point, s: G1Point, t_1: G1Point, t_2: G1Point) -> Self {
        Proof { a, s, t_1, t_2 }
    }

    pub fn get_a(&self) -> &G1Point {
        &self.a
    }
    pub fn get_s(&self) -> &G1Point {
        &self.s
    }

    pub fn get_t_1(&self) -> &G1Point {
        &self.t_1
    }

    pub fn get_t_2(&self) -> &G1Point {
        &self.t_2
    }
}
