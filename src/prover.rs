use merlin::Transcript;

use crate::transcript::TranscriptProtocol;
use ark_ec::short_weierstrass_jacobian::GroupAffine;
use ark_ff::{PrimeField, ToBytes};
use ark_serialize::{CanonicalSerialize, SerializationError};
use rand::Rng;
// Use the BN254 curve
use ark_bn254::{g1::Parameters, Fq as BaseField, Fr as ScalarField};
use ark_std::Zero;

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
}
