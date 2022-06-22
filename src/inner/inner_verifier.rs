use crate::errors::proof_error::throw;
use crate::ProofError;
use crate::{transcript::TranscriptProtocol, Utils};
use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, One, PrimeField};
use merlin::Transcript;
use std::io::Error;

use super::inner_proof::Proof;

pub struct Verifier<'a> {
    transcript: &'a mut Transcript,
}

impl<'a> Verifier<'a> {
    pub fn new(transcript: &'a mut Transcript) -> Self {
        transcript.domain_sep(b"InnerProductArgument");
        Verifier { transcript }
    }

    pub fn verify_proof(&mut self, proof: &Proof) -> Result<(), Error> {
        if true {
            return Ok(());
        } else {
            return Err(throw(ProofError::ProofValidationError));
        }
    }
}
