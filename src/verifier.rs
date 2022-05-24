use ark_bn254::g1::Parameters;
use ark_ec::short_weierstrass_jacobian::GroupAffine;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::PrimeField;
use merlin::Transcript;

use crate::{
    schnorr_proof::{SchnorrProof, SchnorrProofError},
    transcript::TranscriptProtocol,
};

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

    pub fn verify_proof(&mut self, proof: &SchnorrProof) -> Result<(), SchnorrProofError> {
        let a_ref = proof.get_a();
        let z_ref = proof.get_z();

        self.transcript.append_point(b"a", a_ref);

        let e = self.transcript.challenge_scalar(b"e");

        self.transcript.append_scalar(b"z", z_ref);

        println!("VERIFIER _________________________________________________________________________________________________________________________________");
        println!("a: {:?} - on curve {}", *a_ref, a_ref.is_on_curve());
        println!("e: {:?}", e);
        println!("z: {:?}", *z_ref);
        println!("VERIFIER _________________________________________________________________________________________________________________________________");

        let eh = self.h.mul(e.into_repr()).into_affine();
        let a_plus_eh = *a_ref + eh;
        let zg = self.g.mul(z_ref.into_repr()).into_affine();

        if a_plus_eh == zg {
            return Ok(());
        } else {
            return Err(SchnorrProofError::ProofVerificationError);
        }
    }
}
