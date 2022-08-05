use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};

use ark_serialize::*;

#[derive(Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct RangeProof {
    a: G1Point,
    s: G1Point,
    t_1: G1Point,
    t_2: G1Point,
    t_hat: ScalarField,
    mu: ScalarField,
    a_t: G1Point,
    s_ab: ScalarField,
    s_tau: ScalarField,
}
impl RangeProof {
    pub fn new(
        a: G1Point,
        s: G1Point,
        t_1: G1Point,
        t_2: G1Point,
        t_hat: ScalarField,
        mu: ScalarField,
        a_t: G1Point,
        s_ab: ScalarField,
        s_tau: ScalarField,
    ) -> Self {
        RangeProof {
            a,
            s,
            t_1,
            t_2,
            t_hat,
            mu,
            a_t,
            s_ab,
            s_tau,
        }
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

    pub fn get_t_hat(&self) -> &ScalarField {
        &self.t_hat
    }

    pub fn get_mu(&self) -> &ScalarField {
        &self.mu
    }

    pub fn get_a_t(&self) -> &G1Point {
        &self.a_t
    }

    pub fn get_s_ab(&self) -> &ScalarField {
        &self.s_ab
    }

    pub fn get_s_tau(&self) -> &ScalarField {
        &self.s_tau
    }
}
