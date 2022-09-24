use crate::errors::proof_error::throw;
use crate::{
    InnerVerifier, ProofError, RangeVerifier, SigmaABVerifier, SigmaRVerifier, SigmaSKVerifier,
    SigmaYVerifier, TranscriptProtocol, ZeroMTProof,
};
use ark_bn254::G1Affine as G1Point;

use merlin::Transcript;
use std::io::Error;
pub struct ZeroMTVerifier<'a> {
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
        ZeroMTVerifier {
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

    pub fn verify_proof(
        &mut self,
        proof: &ZeroMTProof,
        transcript: &mut Transcript,
    ) -> Result<(), Error> {
        transcript.domain_sep(b"ZeroMTProof");

        let mut range_verifier: RangeVerifier =
            RangeVerifier::new(self.g, self.h, self.c_vec.len() + 1, self.n);

        let (range_proof_result, x_verifier, y_verifier, z_verifier) =
            range_verifier.verify_proof(proof.get_range_proof(), transcript);

        let (h_first_vec_verifier, phu_verifier): (Vec<G1Point>, G1Point) = range_verifier
            .get_ipa_arguments(
                &x_verifier,
                &y_verifier,
                &z_verifier,
                proof.get_range_proof().get_mu(),
                proof.get_range_proof().get_a(),
                proof.get_range_proof().get_s(),
                self.h,
                self.g_vec,
                self.h_vec,
            );

        let inner_result = InnerVerifier::new(
            self.g_vec,
            &h_first_vec_verifier,
            &phu_verifier,
            proof.get_range_proof().get_t_hat(),
            self.u,
        )
        .verify_proof_multiscalar(proof.get_inner_proof(), transcript);

        let sigma_ab_result = SigmaABVerifier::new(self.g, self.d, self.c_r, self.c_l, self.c_vec)
            .verify_proof(proof.get_sigma_ab_proof(), transcript);

        let sigma_y_result = SigmaYVerifier::new(self.y, self.y_bar, self.c_vec, self.c_bar_vec)
            .verify_proof(proof.get_sigma_y_proof(), transcript);

        let sigma_sk_result = SigmaSKVerifier::new(self.g, self.y)
            .verify_proof(proof.get_sigma_sk_proof(), transcript);

        let sigma_r_result =
            SigmaRVerifier::new(self.g, self.d).verify_proof(proof.get_sigma_r_proof(), transcript);

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
}
