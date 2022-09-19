use crate::errors::proof_error::throw;
use crate::{
    InnerVerifier, ProofError, RangeVerifier, SigmaABVerifier, SigmaRVerifier, SigmaSKVerifier,
    SigmaYVerifier, TranscriptProtocol, Utils, ZeroMTProof,
};
use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, One, PrimeField};
use merlin::Transcript;
use std::io::Error;
pub struct ZeroMTVerifier<'a> {
    transcript: &'a mut Transcript,
    g: &'a G1Point,
    h: &'a G1Point,
    n: usize,
    g_vec: &'a Vec<G1Point>,
    h_vec: &'a Vec<G1Point>,
    u: &'a G1Point,
    d: &'a G1Point,
    c_r: &'a G1Point,
    c_l: &'a G1Point,
    c_vec: &'a Vec<G1Point>,
    c_bar_vec: &'a Vec<G1Point>,
    y: &'a G1Point,
    y_bar: &'a Vec<G1Point>,
}

impl<'a> ZeroMTVerifier<'a> {
    pub fn new(
        transcript: &'a mut Transcript,
        g: &'a G1Point,
        h: &'a G1Point,
        n: usize,
        g_vec: &'a Vec<G1Point>,
        h_vec: &'a Vec<G1Point>,
        u: &'a G1Point,
        d: &'a G1Point,
        c_r: &'a G1Point,
        c_l: &'a G1Point,
        c_vec: &'a Vec<G1Point>,
        c_bar_vec: &'a Vec<G1Point>,
        y: &'a G1Point,
        y_bar: &'a Vec<G1Point>,
    ) -> Self {
        transcript.domain_sep(b"ZeroMTProof");
        ZeroMTVerifier {
            transcript,
            g,
            h,
            n,
            g_vec,
            h_vec,
            u,
            d,
            c_r,
            c_l,
            c_vec,
            c_bar_vec,
            y,
            y_bar,
        }
    }

    pub fn verify_proof(&mut self, proof: &ZeroMTProof) -> Result<(), Error> {
        let (range_proof_result, x, y, z) =
            RangeVerifier::new(self.transcript, self.g, self.h, self.c_vec.len(), self.n)
                .verify_proof(proof.get_range_proof());

        let (u, h_first_vec, phu) = Self::get_inner_arguments(
            self.c_vec.len() + 1,
            self.n,
            &x,
            &y,
            &z,
            proof.get_range_proof().get_a(),
            proof.get_range_proof().get_s(),
            self.h,
            self.g_vec,
            self.h_vec,
            self.u,
            proof.get_range_proof().get_mu(),
        );

        let inner_result = InnerVerifier::new(
            self.transcript,
            self.g_vec,
            &h_first_vec,
            &phu,
            proof.get_range_proof().get_t_hat(),
            &u,
        )
        .verify_proof_multiscalar(proof.get_inner_proof());

        let sigma_ab_result = SigmaABVerifier::new(
            self.transcript,
            self.g,
            self.d,
            self.c_r,
            self.c_l,
            self.c_vec,
        )
        .verify_proof(proof.get_sigma_ab_proof());

        let sigma_y_result = SigmaYVerifier::new(
            self.transcript,
            self.y,
            self.y_bar,
            self.c_vec,
            self.c_bar_vec,
        )
        .verify_proof(proof.get_sigma_y_proof());

        let sigma_sk_result = SigmaSKVerifier::new(self.transcript, self.g, self.y)
            .verify_proof(proof.get_sigma_sk_proof());

        let sigma_r_result = SigmaRVerifier::new(self.transcript, self.g, self.d)
            .verify_proof(proof.get_sigma_r_proof());

        let proof_check: bool = range_proof_result.is_ok()
            && sigma_sk_result.is_ok()
            && sigma_r_result.is_ok()
            && sigma_ab_result.is_ok()
            && sigma_y_result.is_ok()
            && inner_result.is_ok();

        if proof_check {
            return Ok(());
        } else {
            return Err(throw(ProofError::ProofValidationError));
        }
    }

    fn get_inner_arguments(
        m: usize,
        n: usize,
        x: &ScalarField,
        y: &ScalarField,
        z: &ScalarField,
        a: &G1Point,
        s: &G1Point,
        h: &G1Point,
        g_vec: &Vec<G1Point>,
        h_vec: &Vec<G1Point>,
        u: &G1Point,
        mu: &ScalarField,
    ) -> (G1Point, Vec<G1Point>, G1Point) {
        let h_first_vec: Vec<G1Point> = (0..m * n)
            .map(|i: usize| {
                h_vec[i]
                    .mul(y.pow([(i as u64)]).inverse().unwrap().into_repr())
                    .into_affine()
            })
            .collect();

        let p: G1Point = *a
            + s.mul(x.into_repr()).into_affine()
            + -Utils::inner_product_point_scalar(
                &g_vec,
                &Utils::generate_scalar_exp_vector(m * n, &ScalarField::one()),
            )
            .unwrap()
            .mul((z).into_repr())
            .into_affine()
            + Utils::inner_product_point_scalar(
                &h_first_vec,
                &Utils::generate_scalar_exp_vector(m * n, &y),
            )
            .unwrap()
            .mul((z).into_repr())
            .into_affine()
            + (1..=m)
                .map(|j: usize| {
                    Utils::inner_product_point_scalar(
                        &h_first_vec[((j - 1) * n)..(j * n)].to_vec(),
                        &Utils::generate_scalar_exp_vector(n, &ScalarField::from(2)),
                    )
                    .unwrap()
                    .mul((z.pow([1 + (j as u64)])).into_repr())
                    .into_affine()
                })
                .sum::<G1Point>();
        let phu: G1Point = p + -h.mul(mu.into_repr()).into_affine();

        (*u, h_first_vec, phu)
    }
}
