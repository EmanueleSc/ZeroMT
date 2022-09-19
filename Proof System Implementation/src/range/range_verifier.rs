use crate::errors::proof_error::throw;
use crate::ProofError;
use crate::{transcript::TranscriptProtocol, Utils};
use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};

use ark_ff::Field;
use merlin::Transcript;
use std::io::Error;

use super::range_proof::RangeProof;

pub struct RangeVerifier<'a> {
    transcript: &'a mut Transcript,
    m: usize,
    g: &'a G1Point,
    h: &'a G1Point,
    n: usize,
}

impl<'a> RangeVerifier<'a> {
    pub fn new(
        transcript: &'a mut Transcript,
        g: &'a G1Point,
        h: &'a G1Point,
        m: usize,
        n: usize,
    ) -> Self {
        transcript.domain_sep(b"RangeProof");
        RangeVerifier {
            transcript,
            m,
            g,
            h,
            n,
        }
    }

    pub fn verify_proof(
        &mut self,
        proof: &RangeProof,
    ) -> (Result<(), Error>, ScalarField, ScalarField, ScalarField) {
        let _result = self.transcript.append_point(b"A", proof.get_a());
        let _result = self.transcript.append_point(b"S", proof.get_s());

        let y: ScalarField = self.transcript.challenge_scalar(b"y");
        let z: ScalarField = self.transcript.challenge_scalar(b"z");

        let _result = self.transcript.append_point(b"T1", proof.get_t_1());
        let _result = self.transcript.append_point(b"T2", proof.get_t_2());

        let x: ScalarField = self.transcript.challenge_scalar(b"x");

        let _result = self.transcript.append_scalar(b"t_hat", proof.get_t_hat());
        let _result = self.transcript.append_scalar(b"mu", proof.get_mu());
        let _result = self.transcript.append_point(b"A_t", proof.get_a_t());

        let c: ScalarField = self.transcript.challenge_scalar(b"c");

        let _result = self.transcript.append_scalar(b"s_ab", proof.get_s_ab());
        let _result = self.transcript.append_scalar(b"s_tau", proof.get_s_tau());

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
