use crate::errors::proof_error::throw;
use crate::ProofError;
use crate::{transcript::TranscriptProtocol, Utils};
use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, PrimeField};
use merlin::Transcript;
use std::io::Error;

use super::inner_halo_proof::InnerHaloProof;

pub struct InnerHaloVerifier<'a> {
    g_vec: &'a Vec<G1Point>,       // G vector of group elements
    b_vec: &'a Vec<ScalarField>,   // use x challange to derive the b_vec = (1,x,x^2,...,x^d)
    h: &'a G1Point,                // H single group element (instead of h_vec)
    t: &'a G1Point,                // T commitment to polynomial t(x) -> t = <t_vec, g_vec> + r * h
    t_hat: &'a ScalarField,        // the polynomial t(x)=t_hat (evaluates to t_hat at point x)
    u: &'a G1Point,                // group element become the first verifer challange
}

impl<'a> InnerHaloVerifier<'a> {
    pub fn new(
        g_vec: &'a Vec<G1Point>,
        b_vec: &'a Vec<ScalarField>,
        h: &'a G1Point,
        t: &'a G1Point, 
        t_hat: &'a ScalarField,
        u: &'a G1Point,
    ) -> Self {
        InnerHaloVerifier {
            g_vec,
            b_vec,
            h,
            t,
            t_hat,
            u,
        }
    }

    pub fn verify_proof(
        &mut self,
        proof: &InnerHaloProof,
        transcript: &mut Transcript,
    ) -> Result<(), Error> {
        transcript.domain_sep(b"InnerProductArgument");

        let t_first: G1Point = *self.t + self.u.mul((self.t_hat).into_repr()).into_affine();

        self.inner_product_argument(self.g_vec, self.b_vec, self.h, self.u, &t_first, proof, transcript)
    }
    
    fn inner_product_argument(
        &mut self,
        g_vec: &Vec<G1Point>,
        b_vec: &'a Vec<ScalarField>,
        h: &'a G1Point,
        u: &G1Point,
        t_first: &G1Point,
        proof: &InnerHaloProof,
        transcript: &mut Transcript,
    ) -> Result<(), Error> {

        // ========== RAUND 1 ==========
        let l_one: G1Point = proof.get_l_vec()[0];
        let r_one: G1Point = proof.get_r_vec()[0];

        let _result = transcript.append_point(b"l_one", &l_one);
        let _result = transcript.append_point(b"r_one", &r_one);
        let m_one: ScalarField = transcript.challenge_scalar(b"m_one");


        // ========== RAUND 0 ==========
        let l_zero: G1Point = proof.get_l_vec()[1];
        let r_zero: G1Point = proof.get_r_vec()[1];

        let _result = transcript.append_point(b"l_zero", &l_zero);
        let _result = transcript.append_point(b"r_zero", &r_zero);
        let m_zero: ScalarField = transcript.challenge_scalar(b"m_zero");


        // After final round
        let t_zero: G1Point = l_zero.mul(m_zero.pow([2]).into_repr()).into_affine()
                            + l_one.mul(m_one.pow([2]).into_repr()).into_affine()
                            + *t_first
                            + r_zero.mul(m_zero.pow([2]).inverse().unwrap().into_repr()).into_affine()
                            + r_one.mul(m_one.pow([2]).inverse().unwrap().into_repr()).into_affine();
        
        // Compute g_zero and b_zero 
        let s_vec_one: Vec<ScalarField> = vec![m_one.inverse().unwrap(), m_one];
        let g_vec_one: Vec<G1Point> = g_vec[..2].to_vec();
        let g_one: G1Point = Utils::inner_product_point_scalar(&g_vec_one, &s_vec_one).unwrap();
        let s_vec_zero: Vec<ScalarField> = vec![m_zero.inverse().unwrap(), m_zero];
        let g_vec_zero: Vec<G1Point> = vec![g_one, g_vec[2..][0]];
        let b_vec_one: Vec<ScalarField> = b_vec[..2].to_vec();
        let b_one: ScalarField = Utils::inner_product_scalar_scalar(&s_vec_one, &b_vec_one).unwrap();
        let b_vec_zero: Vec<ScalarField> = vec![b_one, b_vec[2..][0]];

        let g_zero: G1Point = Utils::inner_product_point_scalar(&g_vec_zero, &s_vec_zero).unwrap();
        let b_zero: ScalarField = Utils::inner_product_scalar_scalar(&b_vec_zero, &s_vec_zero).unwrap();

        // SCHNORR
        let r_comm: G1Point = *proof.get_r();
        let _result = transcript.append_point(b"R", &r_comm);
        let x: ScalarField = transcript.challenge_scalar(b"x");

        let z_one: ScalarField = *proof.get_z_one();
        let z_two: ScalarField = *proof.get_z_two();

        let _result = transcript.append_scalar(b"z_one", &z_one);
        let _result = transcript.append_scalar(b"z_two", &z_two);
        
        let left_eq: G1Point = t_zero.mul(x.into_repr()).into_affine()
                             + r_comm;

        let right_eq: G1Point = (g_zero + u.mul(b_zero.into_repr()).into_affine()).mul(z_one.into_repr()).into_affine()
                              + h.mul(z_two.into_repr()).into_affine();

        if left_eq == right_eq {
            return Ok(());
        }  else {
            return Err(throw(ProofError::ProofValidationError));
        }
    }
}
