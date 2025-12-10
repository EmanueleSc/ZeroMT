use crate::transcript::TranscriptProtocol;
use crate::utils::Utils;
use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, PrimeField};

use merlin::Transcript;

use super::inner_sigma_proof::InnerSigmaProof;

pub struct InnerSigmaProver<'a> {
    g_vec: &'a Vec<G1Point>,
    h_vec: &'a Vec<G1Point>,
    t: &'a G1Point,
    c: &'a ScalarField,
    a_vec: &'a Vec<ScalarField>,
    b_vec: &'a Vec<ScalarField>,
    u: &'a G1Point,
}

impl<'a> InnerSigmaProver<'a> {
    pub fn new(
        g_vec: &'a Vec<G1Point>,
        h_vec: &'a Vec<G1Point>,
        t: &'a G1Point,
        c: &'a ScalarField,
        a_vec: &'a Vec<ScalarField>,
        b_vec: &'a Vec<ScalarField>,
        u: &'a G1Point,
    ) -> Self {
        InnerSigmaProver {
            g_vec,
            h_vec,
            t,
            c,
            a_vec,
            b_vec,
            u,
        }
    }

    pub fn generate_proof(&mut self, transcript: &mut Transcript) -> InnerSigmaProof {
        transcript.domain_sep(b"InnerProductArgument");
        let y: ScalarField = transcript.challenge_scalar(b"y");
        let uy: G1Point = self.u.mul((y).into_repr()).into_affine();
        let t_first: G1Point = *self.t + uy.mul((self.c).into_repr()).into_affine();

        self.inner_product_argument(
            self.g_vec, self.h_vec, &uy, &t_first, self.a_vec, self.b_vec, transcript,
        )
    }

    fn inner_product_argument(
        &mut self,
        g_vec: &Vec<G1Point>,
        h_vec: &Vec<G1Point>,
        u: &G1Point,
        t: &G1Point,
        a_vec: &Vec<ScalarField>,
        b_vec: &Vec<ScalarField>,
        transcript: &mut Transcript,
    ) -> InnerSigmaProof {
        let n: usize = g_vec.len();
        if n == 1 {
            let a: ScalarField = a_vec[0];
            let b: ScalarField = b_vec[0];
            let _result = transcript.append_scalar(b"a", &a);
            let _result = transcript.append_scalar(b"b", &b);
            InnerSigmaProof::new(a, b, [].to_vec(), [].to_vec())
        } else {
            let n_first = n / 2;

            let a_hi: Vec<ScalarField> = a_vec[n_first..].to_vec(); 
            let a_lo: Vec<ScalarField> = a_vec[..n_first].to_vec(); 
            let b_hi: Vec<ScalarField> = b_vec[n_first..].to_vec();
            let b_lo: Vec<ScalarField> = b_vec[..n_first].to_vec();

            let g_hi: Vec<G1Point> = g_vec[n_first..].to_vec();
            let g_lo: Vec<G1Point> = g_vec[..n_first].to_vec();
            let h_hi: Vec<G1Point> = h_vec[n_first..].to_vec();
            let h_lo: Vec<G1Point> = h_vec[..n_first].to_vec();
            
            let c_l: ScalarField = Utils::inner_product_scalar_scalar(&a_hi, &b_lo).unwrap();
            let c_r: ScalarField = Utils::inner_product_scalar_scalar(&a_lo, &b_hi).unwrap();

            let l: G1Point =
                Utils::pedersen_vector_commitment(
                    &c_l, 
                    &u, 
                    &a_hi, 
                    &g_lo, 
                    &b_lo, 
                    &h_hi)
                    .unwrap();

            let r: G1Point =
                Utils::pedersen_vector_commitment(
                    &c_r, 
                    &u, 
                    &a_lo, 
                    &g_hi, 
                    &b_hi, 
                    &h_lo)
                    .unwrap();

            let mut l_vec: Vec<G1Point> = [l].to_vec();
            let mut r_vec: Vec<G1Point> = [r].to_vec();

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

            let a_first_lo: Vec<ScalarField> = Utils::product_scalar(&x, &a_lo);
            let a_first: Vec<ScalarField> =
                Utils::sum_scalar_scalar(&a_first_lo, &a_hi).unwrap();

            let b_first_hi: Vec<ScalarField> = Utils::product_scalar(&x, &b_hi);
            let b_first: Vec<ScalarField> =
                Utils::sum_scalar_scalar(&b_lo, &b_first_hi).unwrap();

            let rec_proof: InnerSigmaProof = self.inner_product_argument(
                &g_first, 
                &h_first, 
                u, 
                &t_first, 
                &a_first, 
                &b_first, 
                transcript,
            );
            l_vec.append(&mut rec_proof.get_l_vec().clone());
            r_vec.append(&mut rec_proof.get_r_vec().clone());

            InnerSigmaProof::new(*rec_proof.get_a(), *rec_proof.get_b(), l_vec, r_vec)
        }
    }
}
