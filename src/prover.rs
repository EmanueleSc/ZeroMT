use merlin::Transcript;

use crate::{schnorr_proof::SchnorrProof, transcript::TranscriptProtocol};
use ark_bn254::{g1::Parameters, Fr as ScalarField};
use ark_ec::short_weierstrass_jacobian::GroupAffine;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::PrimeField;
use ark_std::UniformRand;
use rand::prelude::ThreadRng;

pub struct Prover<'a> {
    transcript: &'a mut Transcript,
    g: &'a GroupAffine<Parameters>,
    h: &'a GroupAffine<Parameters>,
    w: &'a ScalarField,
}

impl<'a> Prover<'a> {
    pub fn new(
        transcript: &'a mut Transcript,
        g: &'a GroupAffine<Parameters>,
        h: &'a GroupAffine<Parameters>,
        w: &'a ScalarField,
    ) -> Self {
        transcript.domain_sep(b"SchnorrProof");

        return Prover {
            transcript,
            g,
            h,
            w,
        };
    }

    pub fn generate_proof(&mut self) -> SchnorrProof {
        let mut rng: ThreadRng = ark_std::rand::thread_rng();
        let r = ScalarField::rand(&mut rng);
        let a = self.g.mul(r.into_repr()).into_affine();

        self.transcript.append_point(b"a", &a);

        let e = self.transcript.challenge_scalar(b"e");

        let z = (*self.w * e) + r;
        self.transcript.append_scalar(b"z", &z);

        println!("PROVER _________________________________________________________________________________________________________________________________");
        println!("a: {:?} - on curve {}", a, a.is_on_curve());
        println!("e: {:?}", e);
        println!("z: {:?}", z);
        println!("PROVER _________________________________________________________________________________________________________________________________");
        return SchnorrProof::new(a, z);
    }
}
