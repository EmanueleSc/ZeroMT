use crate::sigma_r::sigma_r_proof::SigmaRProof;
use crate::transcript::TranscriptProtocol;
use crate::utils::Utils;
use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::PrimeField;
use ark_std::rand::Rng;
use merlin::Transcript;

pub struct SigmaRProver<'a> {
    transcript: &'a mut Transcript,
    /// public generator
    g: &'a G1Point,
    r: &'a ScalarField,
}

impl<'a> SigmaRProver<'a> {
    pub fn new(transcript: &'a mut Transcript, g: &'a G1Point, r: &'a ScalarField) -> Self {
        transcript.domain_sep(b"SigmaR");
        SigmaRProver { transcript, g, r }
    }

    pub fn generate_proof<R: Rng>(&mut self, rng: &mut R) -> SigmaRProof {
        let k_r: ScalarField = Utils::get_n_random_scalars(1, rng)[0];
        let a_d: G1Point = self.g.mul(k_r.into_repr()).into_affine();
        let _result = self.transcript.append_point(b"A_D", &a_d);

        let c: ScalarField = self.transcript.challenge_scalar(b"c");
        let s_r: ScalarField = (*self.r * c) + k_r;
        let _result = self.transcript.append_scalar(b"s_r", &s_r);

        SigmaRProof::new(a_d, s_r)
    }
}
