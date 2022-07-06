use crate::transcript::TranscriptProtocol;
use crate::ProofError;
use crate::{errors::proof_error::throw, sigma_ab::sigma_ab_proof::SigmaABProof};
use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, PrimeField};
use merlin::Transcript;
use std::io::Error;

pub struct SigmaABVerifier<'a> {
    transcript: &'a mut Transcript,
    /// public generator
    g: &'a G1Point,
    d: &'a G1Point,
    c_r: &'a G1Point,
    c_l: &'a G1Point,
    c_vec: &'a Vec<G1Point>,
    a: usize,
}

impl<'a> SigmaABVerifier<'a> {
    pub fn new(
        transcript: &'a mut Transcript,
        g: &'a G1Point,
        d: &'a G1Point,
        c_r: &'a G1Point,
        c_l: &'a G1Point,
        c_vec: &'a Vec<G1Point>,
        a: usize,
    ) -> Self {
        transcript.domain_sep(b"SigmaAB");

        SigmaABVerifier {
            transcript,
            g,
            d,
            c_r,
            c_l,
            c_vec,
            a,
        }
    }

    pub fn verify_proof(&mut self, proof: &SigmaABProof) -> Result<(), Error> {
        let z: ScalarField = self.transcript.challenge_scalar(b"z");

        let _result = self.transcript.append_point(b"A_ab", proof.get_a_ab());

        let c: ScalarField = self.transcript.challenge_scalar(b"c");

        let _result = self.transcript.append_scalar(b"s_ab", proof.get_s_ab());
        let _result = self.transcript.append_scalar(b"s_sk", proof.get_s_sk());

        let left_eq_sum_d_z: G1Point = (1..=self.a)
            .map(|i| self.d.mul(z.pow([2 + (i as u64)])).into_affine())
            .sum::<G1Point>();

        let left_eq_c_r_d_z: G1Point = (self.c_r.into_projective()
            - self.d.mul(ScalarField::from(self.a as i128)))
        .into_affine()
        .mul(z.pow([2]).into_repr())
        .into_affine();

        let left_eq: G1Point = (left_eq_c_r_d_z + left_eq_sum_d_z)
            .mul(proof.get_s_sk().into_repr())
            .into_affine()
            + self.g.mul(proof.get_s_ab().into_repr()).into_affine();

        let right_eq_sum_c_z: G1Point = (1..=self.a)
            .map(|i| {
                self.c_vec
                    .get(i - 1)
                    .unwrap()
                    .mul(z.pow([2 + (i as u64)]))
                    .into_affine()
            })
            .sum::<G1Point>();

        let right_eq_cl_ci_z: G1Point = (self.c_l.into_projective()
            - self.c_vec.iter().sum::<G1Point>().into_projective())
        .into_affine()
        .mul(z.pow([2]).into_repr())
        .into_affine();

        let right_eq: G1Point = (right_eq_sum_c_z + right_eq_cl_ci_z)
            .mul(c.into_repr())
            .into_affine()
            + *proof.get_a_ab();

        if left_eq == right_eq {
            return Ok(());
        } else {
            return Err(throw(ProofError::ProofValidationError));
        }
    }
}
