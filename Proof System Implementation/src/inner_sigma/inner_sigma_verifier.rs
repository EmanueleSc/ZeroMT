use crate::errors::proof_error::throw;
use crate::ProofError;
use crate::{transcript::TranscriptProtocol, Utils};
use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{One, Field, PrimeField};
use merlin::Transcript;
use std::io::Error;

use super::inner_sigma_proof::InnerSigmaProof;

pub struct InnerSigmaVerifier<'a> {
    g_vec: &'a Vec<G1Point>,
    h_vec: &'a Vec<G1Point>,
    t: &'a G1Point,
    c: &'a ScalarField,
    u: &'a G1Point,
}

impl<'a> InnerSigmaVerifier<'a> {
    pub fn new(
        g_vec: &'a Vec<G1Point>,
        h_vec: &'a Vec<G1Point>,
        t: &'a G1Point,
        c: &'a ScalarField,
        u: &'a G1Point,
    ) -> Self {
        InnerSigmaVerifier {
            g_vec,
            h_vec,
            t,
            c,
            u,
        }
    }

    pub fn verify_proof(
        &mut self,
        proof: &InnerSigmaProof,
        transcript: &mut Transcript,
    ) -> Result<(), Error> {
        transcript.domain_sep(b"InnerProductArgument");
        let y: ScalarField = transcript.challenge_scalar(b"y");
        let uy: G1Point = self.u.mul((y).into_repr()).into_affine();
        let t_first: G1Point = *self.t + uy.mul((self.c).into_repr()).into_affine();

        self.inner_product_argument(self.g_vec, self.h_vec, &uy, &t_first, proof, transcript)
    }

    fn inner_product_argument(
        &mut self,
        g_vec: &Vec<G1Point>,
        h_vec: &Vec<G1Point>,
        u: &G1Point,
        t: &G1Point,
        proof: &InnerSigmaProof,
        transcript: &mut Transcript,
    ) -> Result<(), Error> {
        let n: usize = g_vec.len();
        if n == 1 {
            let a: ScalarField = *proof.get_a();
            let b: ScalarField = *proof.get_b();

            let _result = transcript.append_scalar(b"a", &a);
            let _result = transcript.append_scalar(b"b", &b);

            let c: ScalarField = a * b;

            let g: G1Point = g_vec[0];
            let h: G1Point = h_vec[0];

            let to_check: G1Point = 
                g.mul(a.into_repr()).into_affine()
                + h.mul(b.into_repr()).into_affine()
                + u.mul(c.into_repr()).into_affine();

            if *t == to_check {
                return Ok(());
            } else {
                return Err(throw(ProofError::ProofValidationError));
            }
        } else {
            let n_first = n / 2;

            let g_hi: Vec<G1Point> = g_vec[n_first..].to_vec();
            let g_lo: Vec<G1Point> = g_vec[..n_first].to_vec();
            let h_hi: Vec<G1Point> = h_vec[n_first..].to_vec();
            let h_lo: Vec<G1Point> = h_vec[..n_first].to_vec();

            let l: G1Point = proof.get_l_vec()[0];
            let r: G1Point = proof.get_r_vec()[0];
            let _result = transcript.append_point(b"l", &l);
            let _result = transcript.append_point(b"r", &r);
            let x: ScalarField = transcript.challenge_scalar(b"x");

            let g_first_hi: Vec<G1Point> = Utils::product_scalar_point(&x, &g_hi);            
            let g_first: Vec<G1Point> =
                Utils::sum_point_point(&g_lo, &g_first_hi).unwrap();

            let h_first_lo: Vec<G1Point> = Utils::product_scalar_point(&x, &h_lo);
            let h_first: Vec<G1Point> = Utils::sum_point_point(&h_first_lo, &h_hi).unwrap();

            let t_first: G1Point = 
                l 
                + t.mul(x.into_repr()).into_affine()
                + r.mul(x.pow([2]).into_repr()).into_affine();

            let rec_proof: InnerSigmaProof = InnerSigmaProof::new(
                *proof.get_a(),
                *proof.get_b(),
                proof.get_l_vec()[1..].to_vec(),
                proof.get_r_vec()[1..].to_vec(),
            );

            self.inner_product_argument(&g_first, &h_first, u, &t_first, &rec_proof, transcript)
        }
    }

    pub fn verify_proof_multiscalar(
        &mut self,
        proof: &InnerSigmaProof,
        transcript: &mut Transcript,
    ) -> Result<(), Error> {
        transcript.domain_sep(b"InnerProductArgument");
        let y: ScalarField = transcript.challenge_scalar(b"y");
        let uy: G1Point = self.u.mul((y).into_repr()).into_affine();
        let t_first: G1Point = *self.t + uy.mul((self.c).into_repr()).into_affine();

        self.inner_product_argument_multiscalar(
            self.g_vec, 
            self.h_vec, 
            &uy, 
            &t_first, 
            proof, 
            &mut [].to_vec(),
            self.g_vec.len(),
            transcript,
        )
    }

    fn bit_function(&mut self, i: usize, j: usize, n: usize) -> bool {
        let bits: Vec<u8> = Utils::number_to_be_bits_reversed(i, n);
        
        if bits[j] == 1 {
            true
        } else {
            false
        }
    }

    fn get_s_vector(&mut self, x_vec: &Vec<ScalarField>, n: usize) -> Vec<ScalarField> {
        (0..n)
            .map(|i: usize| {
                (0..x_vec.len())
                    .map(|j| {
                        if self.bit_function(i, j as usize, x_vec.len()) {
                            x_vec[j as usize] 
                        } else {
                            ScalarField::one() 
                        }
                    })
                    .reduce(|accum: ScalarField, item: ScalarField| accum * item)
                    .unwrap()
            })
            .collect()
    }

    fn inner_product_argument_multiscalar(
        &mut self,
        g_vec: &Vec<G1Point>,
        h_vec: &Vec<G1Point>,
        u: &G1Point,
        t: &G1Point,
        proof: &InnerSigmaProof,
        x_vec: &mut Vec<ScalarField>,
        n: usize,
        transcript: &mut Transcript,
    ) -> Result<(), Error> {
        if n == 1 {
            let a: ScalarField = *proof.get_a();
            let b: ScalarField = *proof.get_b();

            let _result = transcript.append_scalar(b"a", &a);
            let _result = transcript.append_scalar(b"b", &b);

            let c: ScalarField = a * b;

            let s: Vec<ScalarField> = self.get_s_vector(x_vec, g_vec.len());
            let s_rev: Vec<ScalarField> = s.iter().rev().cloned().collect();

            let g: G1Point = Utils::inner_product_point_scalar(&g_vec, &s).unwrap();
            let h: G1Point = Utils::inner_product_point_scalar(&h_vec, &s_rev).unwrap();

            let to_check: G1Point = g.mul(a.into_repr()).into_affine()
                + h.mul(b.into_repr()).into_affine()
                + u.mul(c.into_repr()).into_affine();

            if *t == to_check {
                return Ok(());
            } else {
                return Err(throw(ProofError::ProofValidationError));
            }
        } else {
            let n_first = n / 2;

            let l: G1Point = proof.get_l_vec()[0];
            let r: G1Point = proof.get_r_vec()[0];
            let _result = transcript.append_point(b"l", &l);
            let _result = transcript.append_point(b"r", &r);
            let x: ScalarField = transcript.challenge_scalar(b"x");

            let mut x_vec_first: Vec<ScalarField> = [x].to_vec();
            x_vec_first.append(x_vec);
        
            let t_first: G1Point = 
                    l 
                    + t.mul(x.into_repr()).into_affine()
                    + r.mul(x.pow([2]).into_repr()).into_affine();

            let rec_proof: InnerSigmaProof = InnerSigmaProof::new(
                *proof.get_a(),
                *proof.get_b(),
                proof.get_l_vec()[1..].to_vec(),
                proof.get_r_vec()[1..].to_vec(),
            );

            self.inner_product_argument_multiscalar(
                g_vec, 
                h_vec, 
                u, 
                &t_first, 
                &rec_proof, 
                &mut x_vec_first, 
                n_first, 
                transcript
            )
        }
    }
}
