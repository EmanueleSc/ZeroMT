use ark_bn254::g1::Parameters;
use ark_ec::short_weierstrass_jacobian::GroupAffine;
use merlin::Transcript;

use crate::transcript::TranscriptProtocol;

pub struct Verifier<'a> {
    transcript: &'a mut Transcript,
    g: &'a GroupAffine<Parameters>,
    h: &'a GroupAffine<Parameters>,
}

impl<'a> Verifier<'a> {
    pub fn new(
        transcript: &'a mut Transcript,
        g: &'a GroupAffine<Parameters>,
        h: &'a GroupAffine<Parameters>,
    ) -> Self {
        transcript.domain_sep(b"SchnorrProof");

        return Verifier { transcript, g, h };
    }
}
