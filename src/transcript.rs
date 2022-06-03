extern crate alloc;
use alloc::vec::Vec;
use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
use ark_ff::{PrimeField, ToBytes};
use ark_serialize::CanonicalSerialize;
use ark_std::Zero;
use merlin::Transcript;
use std::io::Error;

use crate::{errors::transcript_error::throw, TranscriptError};

pub trait TranscriptProtocol {
    /// Appends `label` to the transcript as a domain separator.
    /// Used to insert a proof label in the transcript when it is used in the prover.
    fn domain_sep(&mut self, label: &'static [u8]);

    /// Append a prover `scalar` with the given `label`.
    fn append_scalar(&mut self, label: &'static [u8], scalar: &ScalarField);

    /// Append a prover `point` with the given `label`.
    fn append_point(&mut self, label: &'static [u8], point: &G1Point) -> Result<(), Error>;

    /// Append a prover `point` with the given `label` if it's not an identity/zero element.
    fn validate_and_append_point(
        &mut self,
        label: &'static [u8],
        point: &G1Point,
    ) -> Result<(), Error>;

    /// Compute a verifier `label`ed challenge variable.
    fn challenge_scalar(&mut self, label: &'static [u8]) -> ScalarField;
}

impl TranscriptProtocol for Transcript {
    fn append_scalar(&mut self, label: &'static [u8], scalar: &ScalarField) {
        let mut bytes = Vec::new();
        scalar.serialize(&mut bytes).unwrap();
        self.append_message(label, &bytes[..]);
    }

    fn append_point(&mut self, label: &'static [u8], point: &G1Point) -> Result<(), Error> {
        let mut bytes = Vec::new();
        let write_result = point.write(&mut bytes);
        if write_result.is_ok() {
            self.append_message(label, &bytes[..]);
            return Ok(());
        } else {
            return throw(TranscriptError::PointSerializationError);
        }
    }

    fn domain_sep(&mut self, label: &'static [u8]) {
        self.append_message(b"dom-sep", label);
    }

    fn challenge_scalar(&mut self, label: &'static [u8]) -> ScalarField {
        // Reduce a double-width scalar to ensure a uniform distribution
        let mut buf = [0; 64];
        self.challenge_bytes(label, &mut buf);
        return ScalarField::from_le_bytes_mod_order(&buf);
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
}
