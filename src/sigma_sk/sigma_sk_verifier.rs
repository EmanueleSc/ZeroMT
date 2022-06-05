use crate::transcript::TranscriptProtocol;
use crate::ProofError;
use crate::{errors::proof_error::throw, sigma_sk::sigma_sk_proof::Proof};
use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::PrimeField;
use merlin::Transcript;
use std::io::Error;

pub struct Verifier<'a> {
    transcript: &'a mut Transcript,
    /// public generator
    g: &'a G1Point,
    /// sender public key: y = g^{sk}
    y: &'a G1Point,
}

impl<'a> Verifier<'a> {
    pub fn new(transcript: &'a mut Transcript, g: &'a G1Point, y: &'a G1Point) -> Self {
        transcript.domain_sep(b"SigmaSK");
        Verifier { transcript, g, y }
    }

    pub fn verify_proof(&mut self, proof: &Proof) -> Result<(), Error> {
        self.transcript.append_point(b"A_y", proof.get_a_y());

        let c: ScalarField = self.transcript.challenge_scalar(b"c");
        self.transcript.append_scalar(b"s_sk", proof.get_s_sk());

        let left_eq: G1Point = self.g.mul(proof.get_s_sk().into_repr()).into_affine();
        let right_eq: G1Point = *proof.get_a_y() + (self.y.mul(c.into_repr()).into_affine());

        if left_eq == right_eq {
            return Ok(());
        } else {
            return Err(throw(ProofError::ProofValidationError));
        }
    }
}
