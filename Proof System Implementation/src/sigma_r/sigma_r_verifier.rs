use crate::transcript::TranscriptProtocol;
use crate::ProofError;
use crate::{errors::proof_error::throw, sigma_r::sigma_r_proof::SigmaRProof};
use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::PrimeField;
use merlin::Transcript;
use std::io::Error;

pub struct SigmaRVerifier<'a> {
    /// public generator
    g: &'a G1Point,
    d: &'a G1Point,
}

impl<'a> SigmaRVerifier<'a> {
    pub fn new(g: &'a G1Point, d: &'a G1Point) -> Self {
        SigmaRVerifier { g, d }
    }

    pub fn verify_proof(
        &mut self,
        proof: &SigmaRProof,
        transcript: &mut Transcript,
    ) -> Result<(), Error> {
        transcript.domain_sep(b"SigmaR");

        let _result = transcript.append_point(b"A_D", proof.get_a_d());

        let c: ScalarField = transcript.challenge_scalar(b"c");
        let _result = transcript.append_scalar(b"s_r", proof.get_s_r());

        let left_eq: G1Point = self.g.mul(proof.get_s_r().into_repr()).into_affine();
        let right_eq: G1Point = *proof.get_a_d() + (self.d.mul(c.into_repr()).into_affine());

        if left_eq == right_eq {
            return Ok(());
        } else {
            return Err(throw(ProofError::ProofValidationError));
        }
    }
}
