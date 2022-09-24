use crate::{
    InnerProof, InnerProver, RangeProof, RangeProver, SigmaABProof, SigmaABProver, SigmaRProof,
    SigmaRProver, SigmaSKProof, SigmaSKProver, SigmaYProof, SigmaYProver, TranscriptProtocol,
    ZeroMTProof,
};
use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
use ark_std::rand::Rng;
use merlin::Transcript;

pub struct ZeroMTProver<'a> {
    g: &'a G1Point,
    h: &'a G1Point,
    remaining_balance: usize,
    amounts: &'a Vec<usize>,
    g_vec: &'a Vec<G1Point>,
    h_vec: &'a Vec<G1Point>,
    u: &'a G1Point,
    n: usize,
    d: &'a G1Point,
    c_r: &'a G1Point,
    sk: &'a ScalarField,
    r: &'a ScalarField,
    y: &'a G1Point,
    y_bar: &'a Vec<G1Point>,
}

impl<'a> ZeroMTProver<'a> {
    pub fn new(
        g: &'a G1Point,
        h: &'a G1Point,
        remaining_balance: usize,
        amounts: &'a Vec<usize>,
        g_vec: &'a Vec<G1Point>,
        h_vec: &'a Vec<G1Point>,
        u: &'a G1Point,
        n: usize,
        d: &'a G1Point,
        c_r: &'a G1Point,
        sk: &'a ScalarField,
        r: &'a ScalarField,
        y: &'a G1Point,
        y_bar: &'a Vec<G1Point>,
    ) -> Self {
        ZeroMTProver {
            g,
            h,
            remaining_balance,
            amounts,
            g_vec,
            h_vec,
            u,
            n,
            d,
            c_r,
            sk,
            r,
            y,
            y_bar,
        }
    }

    pub fn generate_proof<R: Rng>(
        &mut self,
        rng: &mut R,
        transcript: &mut Transcript,
    ) -> ZeroMTProof {
        transcript.domain_sep(b"ZeroMTProof");

        let mut range_prover: RangeProver = RangeProver::new(
            self.g,
            self.h,
            self.remaining_balance,
            self.amounts,
            self.g_vec,
            self.h_vec,
            self.n,
        );

        let (range_proof, l_poly_vec, r_poly_vec, x_prover, y_prover, z_prover): (
            RangeProof,
            Vec<ScalarField>,
            Vec<ScalarField>,
            ScalarField,
            ScalarField,
            ScalarField,
        ) = range_prover.generate_proof(rng, transcript);

        let (h_first_vec_prover, phu_prover): (Vec<G1Point>, G1Point) = range_prover
            .get_ipa_arguments(
                &x_prover,
                &y_prover,
                &z_prover,
                range_proof.get_mu(),
                range_proof.get_a(),
                range_proof.get_s(),
                self.h,
                self.g_vec,
                self.h_vec,
            );

        let inner_proof: InnerProof = InnerProver::new(
            self.g_vec,
            &h_first_vec_prover,
            &phu_prover,
            range_proof.get_t_hat(),
            &l_poly_vec,
            &r_poly_vec,
            self.u,
        )
        .generate_proof(transcript);

        let sigma_ab_proof: SigmaABProof = SigmaABProver::new(
            self.g,
            self.d,
            self.c_r,
            self.remaining_balance,
            self.amounts,
            self.sk,
        )
        .generate_proof(rng, transcript);

        let sigma_y_proof: SigmaYProof =
            SigmaYProver::new(self.r, self.y, self.y_bar).generate_proof(rng, transcript);

        let sigma_sk_proof: SigmaSKProof =
            SigmaSKProver::new(self.g, self.sk).generate_proof(rng, transcript);

        let sigma_r_proof: SigmaRProof =
            SigmaRProver::new(self.g, self.r).generate_proof(rng, transcript);

        ZeroMTProof::new(
            range_proof,
            inner_proof,
            sigma_ab_proof,
            sigma_r_proof,
            sigma_sk_proof,
            sigma_y_proof,
        )
    }
}
