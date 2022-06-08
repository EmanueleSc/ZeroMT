use crate::transcript::TranscriptProtocol;
use crate::ProofError;
use crate::{errors::proof_error::throw, sigma_y::sigma_y_proof::Proof};
use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::PrimeField;
use merlin::Transcript;
use std::io::Error;

pub struct Verifier<'a> {
    transcript: &'a mut Transcript,
    /// public generator
    g: &'a G1Point,
    y: &'a G1Point,
    y_bar: &'a Vec<G1Point>,
    c_vec: &'a Vec<G1Point>,
    c_bar_vec: &'a Vec<G1Point>,
}

impl<'a> Verifier<'a> {
    pub fn new(
        transcript: &'a mut Transcript,
        g: &'a G1Point,
        y: &'a G1Point,
        y_bar: &'a Vec<G1Point>,
        c_vec: &'a Vec<G1Point>,
        c_bar_vec: &'a Vec<G1Point>,
    ) -> Self {
        transcript.domain_sep(b"SigmaY");
        Verifier {
            transcript,
            g,
            y,
            y_bar,
            c_vec,
            c_bar_vec,
        }
    }

    pub fn verify_proof(&mut self, proof: &Proof) -> Result<(), Error> {
        self.transcript
            .append_point(b"A_y_bar", proof.get_a_y_bar());

        let c: ScalarField = self.transcript.challenge_scalar(b"c");
        self.transcript.append_scalar(b"s_r", proof.get_s_r());

        let left_eq: G1Point = self
            .y_bar
            .iter()
            .map(|y_i: &G1Point| (self.y.into_projective() - y_i.into_projective()).into_affine())
            .sum::<G1Point>()
            .mul(proof.get_s_r().into_repr())
            .into_affine();

        let right_eq: G1Point = *proof.get_a_y_bar()
            + self
                .c_vec
                .iter()
                .zip(self.c_bar_vec.iter())
                .map(|(c_i, c_bar_i): (&G1Point, &G1Point)| {
                    (c_i.into_projective() - c_bar_i.into_projective()).into_affine()
                })
                .sum::<G1Point>()
                .mul(c.into_repr())
                .into_affine();

        if left_eq == right_eq {
            return Ok(());
        } else {
            return Err(throw(ProofError::ProofValidationError));
        }
    }
}
