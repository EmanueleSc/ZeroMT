use crate::transcript::TranscriptProtocol;
use crate::utils::Utils;
use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, One, PrimeField, Zero};
use ark_std::rand::Rng;
use merlin::Transcript;

use super::inner_proof::Proof;

pub struct Prover<'a> {
    transcript: &'a mut Transcript,
}

impl<'a> Prover<'a> {
    pub fn new(transcript: &'a mut Transcript) -> Self {
        transcript.domain_sep(b"InnerProductArgument");
        Prover { transcript }
    }

    pub fn generate_proof<R: Rng>(&mut self, rng: &mut R) -> Proof {
        Proof::new()
    }
}
