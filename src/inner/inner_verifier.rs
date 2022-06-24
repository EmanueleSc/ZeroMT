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
    g_vec: &'a Vec<G1Point>,
    h_vec: &'a Vec<G1Point>,
    p: &'a G1Point,
    c: &'a ScalarField,
    u: &'a G1Point,
}

impl<'a> Verifier<'a> {
    pub fn new(
        transcript: &'a mut Transcript,
        g_vec: &'a Vec<G1Point>,
        h_vec: &'a Vec<G1Point>,
        p: &'a G1Point,
        c: &'a ScalarField,
        u: &'a G1Point,
    ) -> Self {
        transcript.domain_sep(b"InnerProductArgument");
        Verifier {
            transcript,
            g_vec,
            h_vec,
            p,
            c,
            u,
        }
    }

    pub fn verify_proof(&mut self, proof: &Proof) -> Result<(), Error> {
        let x: ScalarField = self.transcript.challenge_scalar(b"x");
        let ux: G1Point = self.u.mul((x).into_repr()).into_affine();
        let p_first: G1Point = *self.p + ux.mul((self.c).into_repr()).into_affine();
        let mut x_vec: Vec<ScalarField> = [].to_vec();

        self.inner_product_argument(self.g_vec, self.h_vec, &ux, &p_first, proof)
    }

    pub fn verify_proof_multiscalar(&mut self, proof: &Proof) -> Result<(), Error> {
        let x: ScalarField = self.transcript.challenge_scalar(b"x");
        let ux: G1Point = self.u.mul((x).into_repr()).into_affine();
        let p_first: G1Point = *self.p + ux.mul((self.c).into_repr()).into_affine();

        self.inner_product_argument_multiscalar(
            self.g_vec,
            self.h_vec,
            &ux,
            &p_first,
            proof,
            &mut [].to_vec(),
            self.g_vec.len(),
        )
    }

    fn bit_function(&mut self, i: usize, j: usize) -> bool {
        let bits: Vec<u8> = Utils::number_to_be_bits_reversed(i);

        if bits[j] == 1 {
            true
        } else {
            false
        }
    }
    fn get_s_vector(&mut self, x_vec: &mut Vec<ScalarField>, n: usize) -> Vec<ScalarField> {
        (0..n)
            .map(|i: usize| {
                (0..n.log2())
                    .map(|j| {
                        if self.bit_function(i, j as usize) {
                            x_vec[j as usize]
                        } else {
                            x_vec[j as usize].inverse().unwrap()
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
        p: &G1Point,
        proof: &Proof,
        x_vec: &mut Vec<ScalarField>,
        n: usize,
    ) -> Result<(), Error> {
        if n == 1 {
            let a: ScalarField = *proof.get_a();
            let b: ScalarField = *proof.get_b();

            self.transcript.append_scalar(b"a", &a);
            self.transcript.append_scalar(b"b", &b);

            let c: ScalarField = a * b;

            let s: Vec<ScalarField> = self.get_s_vector(x_vec, g_vec.len());
            let s_inverse: Vec<ScalarField> = s
                .iter()
                .map(|scal: &ScalarField| scal.inverse().unwrap())
                .collect();

            let g: G1Point = Utils::inner_product_point_scalar(&g_vec, &s).unwrap();
            let h: G1Point = Utils::inner_product_point_scalar(&h_vec, &s_inverse).unwrap();

            let to_check: G1Point = g.mul(a.into_repr()).into_affine()
                + h.mul(b.into_repr()).into_affine()
                + u.mul(c.into_repr()).into_affine();

            if *p == to_check {
                return Ok(());
            } else {
                return Err(throw(ProofError::ProofValidationError));
            }
        } else {
            let n_first = n / 2;

            let l: G1Point = proof.get_l_vec()[0];
            let r: G1Point = proof.get_r_vec()[0];
            self.transcript.append_point(b"l", &l);
            self.transcript.append_point(b"r", &r);
            let x: ScalarField = self.transcript.challenge_scalar(b"x");

            let mut x_vec_first: Vec<ScalarField> = [x].to_vec();
            x_vec_first.append(x_vec);

            let p_first: G1Point = l.mul(x.pow([2]).into_repr()).into_affine()
                + *p
                + r.mul(x.pow([2]).inverse().unwrap().into_repr())
                    .into_affine();

            let rec_proof: Proof = Proof::new(
                *proof.get_a(),
                *proof.get_b(),
                proof.get_l_vec()[1..].to_vec(),
                proof.get_r_vec()[1..].to_vec(),
            );

            self.inner_product_argument_multiscalar(
                g_vec,
                h_vec,
                u,
                &p_first,
                &rec_proof,
                &mut x_vec_first,
                n_first,
            )
        }
    }

    fn inner_product_argument(
        &mut self,
        g_vec: &Vec<G1Point>,
        h_vec: &Vec<G1Point>,
        u: &G1Point,
        p: &G1Point,
        proof: &Proof,
    ) -> Result<(), Error> {
        let n: usize = g_vec.len();
        if n == 1 {
            let a: ScalarField = *proof.get_a();
            let b: ScalarField = *proof.get_b();

            self.transcript.append_scalar(b"a", &a);
            self.transcript.append_scalar(b"b", &b);

            let c: ScalarField = a * b;

            let g: G1Point = g_vec[0];
            let h: G1Point = h_vec[0];

            let to_check: G1Point = g.mul(a.into_repr()).into_affine()
                + h.mul(b.into_repr()).into_affine()
                + u.mul(c.into_repr()).into_affine();

            if *p == to_check {
                return Ok(());
            } else {
                return Err(throw(ProofError::ProofValidationError));
            }
        } else {
            let n_first = n / 2;

            let g_left: Vec<G1Point> = g_vec[..n_first].to_vec();
            let g_right: Vec<G1Point> = g_vec[n_first..].to_vec();
            let h_left: Vec<G1Point> = h_vec[..n_first].to_vec();
            let h_right: Vec<G1Point> = h_vec[n_first..].to_vec();

            let l: G1Point = proof.get_l_vec()[0];
            let r: G1Point = proof.get_r_vec()[0];
            self.transcript.append_point(b"l", &l);
            self.transcript.append_point(b"r", &r);
            let x: ScalarField = self.transcript.challenge_scalar(b"x");

            let g_first_left: Vec<G1Point> =
                Utils::product_scalar_point(&x.inverse().unwrap(), &g_left);
            let g_first_right: Vec<G1Point> = Utils::product_scalar_point(&x, &g_right);
            let g_first: Vec<G1Point> =
                Utils::sum_point_point(&g_first_left, &g_first_right).unwrap();

            let h_first_left: Vec<G1Point> = Utils::product_scalar_point(&x, &h_left);
            let h_first_right: Vec<G1Point> =
                Utils::product_scalar_point(&x.inverse().unwrap(), &h_right);
            let h_first: Vec<G1Point> =
                Utils::sum_point_point(&h_first_left, &h_first_right).unwrap();

            let p_first: G1Point = l.mul(x.pow([2]).into_repr()).into_affine()
                + *p
                + r.mul(x.pow([2]).inverse().unwrap().into_repr())
                    .into_affine();

            let rec_proof: Proof = Proof::new(
                *proof.get_a(),
                *proof.get_b(),
                proof.get_l_vec()[1..].to_vec(),
                proof.get_r_vec()[1..].to_vec(),
            );

            self.inner_product_argument(&g_first, &h_first, u, &p_first, &rec_proof)
        }
    }
}
