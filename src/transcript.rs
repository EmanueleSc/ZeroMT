use std::io::{Error};
use ark_ff::{PrimeField, ToBytes};
use merlin::Transcript;
use ark_std::Zero;
use ark_bn254::{G1Affine as G1Point, Fr as ScalarField};
use ark_serialize::{CanonicalSerialize};
use crate::custom_errors::{throw, TranscriptError};

pub trait TranscriptProtocol {
    // Append `label` to the transcript as a domain separator (label that should
    // uniquely identify the proof statement).
    fn schnorr_domain_sep(&mut self, label: &'static [u8]);

    // Append a `scalar` with the given `label`.
    fn append_scalar(&mut self, label: &'static [u8], scalar: &ScalarField);

    // Append a `point` with the given `label`.
    fn append_point(
        &mut self, 
        label: &'static [u8], 
        point: &G1Point
    ) -> Result<(), Error>;

    fn validate_and_append_point(
        &mut self, 
        label: &'static [u8], 
        point: &G1Point
    ) -> Result<(), Error>;
    
    // Compute a `label`ed challenge variable.
    fn challenge_scalar(&mut self, label: &'static [u8]) -> ScalarField;
}

impl TranscriptProtocol for Transcript {
    fn schnorr_domain_sep(&mut self, label: &'static [u8]) {
        self.append_message(b"dom-sep", label);
    }

    fn append_scalar(&mut self, label: &'static [u8], scalar: &ScalarField) {
        let mut bytes = Vec::new();
        scalar.serialize(&mut bytes).unwrap();
        self.append_message(label,  &bytes);
    }

    fn append_point(
        &mut self, 
        label: &'static [u8], 
        point: &G1Point) 
    -> Result<(), Error> {
        let mut bytes = Vec::new();
        let write_res = point.write(&mut bytes);
        if write_res.is_ok() {
            self.append_message(label, &bytes);
            return Ok(());
        }
        return write_res;
    }
    
    fn validate_and_append_point(
        &mut self,
        label: &'static [u8],
        point: &G1Point,
    ) -> Result<(), Error> {
        if point.is_zero() {
            return throw(TranscriptError::PointValidationError);
        }
        return self.append_point(label, &point);
    }

    fn challenge_scalar(&mut self, label: &'static [u8]) -> ScalarField {
        // Reduce a double-width scalar to ensure a uniform distribution
        let mut buf = [0; 64];
        self.challenge_bytes(label, &mut buf);
        return ScalarField::from_le_bytes_mod_order(&buf);
    }
}
