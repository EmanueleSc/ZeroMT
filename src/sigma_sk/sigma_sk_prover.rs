use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::PrimeField;
use merlin::Transcript;
use ark_bn254::{G1Affine as G1Point, Fr as ScalarField};
use ark_std::rand::Rng;
use crate::transcript::TranscriptProtocol;
use crate::proof_utils::ProofUtils;
use crate::sigma_sk::sigma_sk_proof::SigmaSkProof;

pub struct Prover<'a> {
    transcript: &'a mut Transcript,
    /// public generator
    g: &'a G1Point,
    /// sender public key: y = g^{sk}
    y: &'a G1Point,
    /// witness: sender private key is a random scalar (!= 0)
    sk: &'a ScalarField,
}

impl<'a> Prover<'a> {
    pub fn new(
        transcript: &'a mut Transcript,
        g: &'a G1Point,
        y: &'a G1Point,
        sk: &'a ScalarField,
    ) -> Self {
        transcript.domain_sep(b"SigmaSK");
        Prover { transcript, g, y, sk }
    }

    pub fn generate_proof<R: Rng>(&mut self, rng: &mut R) -> SigmaSkProof {
        let k_sk = ProofUtils::get_n_random_scalars(1, rng)[0];
        let a_y = self.g.mul(k_sk.into_repr()).into_affine();
        self.transcript.append_point(b"A_y", &a_y);
        
        let c = self.transcript.challenge_scalar(b"c");
        let s_sk = (*self.sk * c) + k_sk;
        self.transcript.append_scalar(b"s_sk", &s_sk);

        SigmaSkProof::new(a_y, s_sk)
    }
}