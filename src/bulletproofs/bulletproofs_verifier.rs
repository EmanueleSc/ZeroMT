use crate::transcript::TranscriptProtocol;
use crate::ProofError;
use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::PrimeField;
use merlin::Transcript;
use std::io::Error;

use super::bulletproofs_proof::Proof;

pub struct Verifier<'a> {
    transcript: &'a mut Transcript,
}

impl<'a> Verifier<'a> {
    pub fn new(transcript: &'a mut Transcript) -> Self {
        transcript.domain_sep(b"Bulletproofs");
        Verifier { transcript }
    }

    pub fn verify_proof(&mut self, proof: &Proof) -> Result<(), Error> {
        self.transcript.append_point(b"A", proof.get_a());
        self.transcript.append_point(b"S", proof.get_s());

        let y: ScalarField = self.transcript.challenge_scalar(b"y");
        let z: ScalarField = self.transcript.challenge_scalar(b"z");

        self.transcript.append_point(b"T1", proof.get_t_1());
        self.transcript.append_point(b"T2", proof.get_t_2());

        let x: ScalarField = self.transcript.challenge_scalar(b"x");

        println!("Verifier y - {:?}", y);
        println!("Verifier x - {:?}", x);
        println!("Verifier z - {:?}", z);

        return Ok(());
    }
}
