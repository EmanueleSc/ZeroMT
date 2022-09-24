use crate::errors::proof_error::throw;
use crate::ProofError;
use crate::{transcript::TranscriptProtocol, Utils};
use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, One, PrimeField};
use merlin::Transcript;
use std::io::Error;

use super::range_proof::RangeProof;

pub struct RangeVerifier<'a> {
    g: &'a G1Point,
    h: &'a G1Point,
    m: usize,
    n: usize,
}

impl<'a> RangeVerifier<'a> {
    pub fn new(g: &'a G1Point, h: &'a G1Point, m: usize, n: usize) -> Self {
        RangeVerifier { g, h, m, n }
    }

    pub fn get_ipa_arguments(
        &mut self,
        x: &ScalarField,
        y: &ScalarField,
        z: &ScalarField,
        mu: &ScalarField,
        a: &G1Point,
        s: &G1Point,
        h: &G1Point,
        g_vec: &Vec<G1Point>,
        h_vec: &Vec<G1Point>,
    ) -> (Vec<G1Point>, G1Point) {
        let h_first_vec: Vec<G1Point> = (0..h_vec.len())
            .map(|i: usize| {
                h_vec[i]
                    .mul(y.pow([(i as u64)]).inverse().unwrap().into_repr())
                    .into_affine()
            })
            .collect();

        let p: G1Point = *a
            + s.mul(x.into_repr()).into_affine()
            + -Utils::inner_product_point_scalar(
                &g_vec,
                &Utils::generate_scalar_exp_vector(g_vec.len(), &ScalarField::one()),
            )
            .unwrap()
            .mul((z).into_repr())
            .into_affine()
            + Utils::inner_product_point_scalar(
                &h_first_vec,
                &Utils::generate_scalar_exp_vector(h_first_vec.len(), &y),
            )
            .unwrap()
            .mul((z).into_repr())
            .into_affine()
            + (1..=self.m)
                .map(|j: usize| {
                    Utils::inner_product_point_scalar(
                        &h_first_vec[((j - 1) * self.n)..(j * self.n)].to_vec(),
                        &Utils::generate_scalar_exp_vector(self.n, &ScalarField::from(2)),
                    )
                    .unwrap()
                    .mul((z.pow([1 + (j as u64)])).into_repr())
                    .into_affine()
                })
                .sum::<G1Point>();
        let phu: G1Point = p + -h.mul(mu.into_repr()).into_affine();

        (h_first_vec, phu)
    }

    pub fn verify_proof(
        &mut self,
        proof: &RangeProof,
        transcript: &mut Transcript,
    ) -> (Result<(), Error>, ScalarField, ScalarField, ScalarField) {
        transcript.domain_sep(b"RangeProof");

        let _result = transcript.append_point(b"A", proof.get_a());
        let _result = transcript.append_point(b"S", proof.get_s());

        let y: ScalarField = transcript.challenge_scalar(b"y");
        let z: ScalarField = transcript.challenge_scalar(b"z");

        let _result = transcript.append_point(b"T1", proof.get_t_1());
        let _result = transcript.append_point(b"T2", proof.get_t_2());

        let x: ScalarField = transcript.challenge_scalar(b"x");

        let _result = transcript.append_scalar(b"t_hat", proof.get_t_hat());
        let _result = transcript.append_scalar(b"mu", proof.get_mu());
        let _result = transcript.append_point(b"A_t", proof.get_a_t());

        let c: ScalarField = transcript.challenge_scalar(b"c");

        let _result = transcript.append_scalar(b"s_ab", proof.get_s_ab());
        let _result = transcript.append_scalar(b"s_tau", proof.get_s_tau());

        let delta_left: ScalarField = (z - (z * z))
            * Utils::generate_scalar_exp_vector(self.m * self.n, &y)
                .iter()
                .sum::<ScalarField>();

        let delta_right: ScalarField = (1..=self.m)
            .map(|j: usize| {
                z.pow([2 + (j as u64)])
                    * Utils::generate_scalar_exp_vector(self.n, &ScalarField::from(2))
                        .iter()
                        .sum::<ScalarField>()
            })
            .sum::<ScalarField>();

        let delta_y_z: ScalarField = delta_left - delta_right;

        let g_exp: ScalarField = (c * *proof.get_t_hat()) - (c * delta_y_z) - *proof.get_s_ab();
        let h_exp: ScalarField = *proof.get_s_tau();

        let left_eq: G1Point = Utils::pedersen_commitment(&g_exp, self.g, &h_exp, self.h);

        let g_scal: ScalarField = c * x;
        let h_scal: ScalarField = c * x * x;

        let right_eq: G1Point = *proof.get_a_t()
            + Utils::pedersen_commitment(&g_scal, proof.get_t_1(), &h_scal, proof.get_t_2());

        if left_eq == right_eq {
            return (Ok(()), x, y, z);
        } else {
            return (Err(throw(ProofError::ProofValidationError)), x, y, z);
        }
    }
}
