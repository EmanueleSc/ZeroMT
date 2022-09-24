use crate::sigma_y::sigma_y_proof::SigmaYProof;
use crate::transcript::TranscriptProtocol;
use crate::utils::Utils;
use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::PrimeField;
use ark_std::rand::Rng;
use merlin::Transcript;

pub struct SigmaYProver<'a> {
    r: &'a ScalarField,
    y: &'a G1Point,
    y_bar: &'a Vec<G1Point>,
}

impl<'a> SigmaYProver<'a> {
    pub fn new(r: &'a ScalarField, y: &'a G1Point, y_bar: &'a Vec<G1Point>) -> Self {
        SigmaYProver { r, y, y_bar }
    }

    pub fn generate_proof<R: Rng>(
        &mut self,
        rng: &mut R,
        transcript: &mut Transcript,
    ) -> SigmaYProof {
        transcript.domain_sep(b"SigmaY");

        let k_r: ScalarField = Utils::get_n_random_scalars(1, rng)[0];

        let a_y_bar: G1Point = self
            .y_bar
            .iter()
            .map(|y_i: &G1Point| (self.y.into_projective() - y_i.into_projective()).into_affine())
            .sum::<G1Point>()
            .mul(k_r.into_repr())
            .into_affine();

        let _result = transcript.append_point(b"A_y_bar", &a_y_bar);

        let c: ScalarField = transcript.challenge_scalar(b"c");
        let s_r: ScalarField = (*self.r * c) + k_r;
        let _result = transcript.append_scalar(b"s_r", &s_r);

        SigmaYProof::new(a_y_bar, s_r)
    }
}
