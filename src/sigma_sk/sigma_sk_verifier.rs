use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::PrimeField;
use merlin::Transcript;
use ark_bn254::{G1Affine as G1Point};
use crate::transcript::TranscriptProtocol;
use crate::sigma_sk::sigma_sk_proof::SigmaSkProof;

pub struct Verifier<'a> {
    transcript: &'a mut Transcript,
    /// public generator
    g: &'a G1Point,
    /// sender public key: y = g^{sk}
    y: &'a G1Point,
}

impl<'a> Verifier<'a> {
    pub fn new(
        transcript: &'a mut Transcript,
        g: &'a G1Point,
        y: &'a G1Point,
    ) -> Self {
        transcript.domain_sep(b"SigmaSK");
        Verifier { transcript, g, y }
    }

    pub fn verify_proof(&mut self, proof: &SigmaSkProof) -> Result<(), String> {
        let a_y = *proof.get_a_y();
        let s_sk = *proof.get_s_sk();
        self.transcript.append_point(b"A_y", &a_y);

        let c = self.transcript.challenge_scalar(b"c");
        self.transcript.append_scalar(b"c", &c);

        let left_eq = self.g.mul(s_sk.into_repr()).into_affine();
        let right_eq = a_y + (self.y.mul(c.into_repr()).into_affine());

        if left_eq == right_eq {
            return Ok(());
        } else {
            return Err(String::from("Verification failed"));
        }
    }
}