extern crate alloc;
use alloc::vec::Vec;
use ark_bn254::{g1::Parameters, Fr as ScalarField};
use ark_ec::short_weierstrass_jacobian::GroupAffine;
use ark_ff::{PrimeField, ToBytes};
use ark_serialize::CanonicalSerialize;
use ark_std::Zero;
use merlin::Transcript;

pub trait TranscriptProtocol {
    /// Appends `label` to the transcript as a domain separator.
    /// Used to insert a proof label in the transcript when it is used in the prover.
    fn domain_sep(&mut self, label: &'static [u8]);

    /// Append a prover `scalar` with the given `label`.
    fn append_scalar(&mut self, label: &'static [u8], scalar: &ScalarField);

    /// Append a prover `point` with the given `label`.
    fn append_point(
        &mut self,
        label: &'static [u8],
        point: &GroupAffine<Parameters>,
    ) -> Result<(), &'static str>;

    /// Append a prover `Vec` of `point` with the given `label`.
    fn append_points_vector(
        &mut self,
        label: &'static [u8],
        points: &Vec<GroupAffine<Parameters>>,
    ) -> Result<(), &'static str>;

    /// Append a prover `point` with the given `label` if it's not an identity/zero element.
    fn validate_and_append_point(
        &mut self,
        label: &'static [u8],
        point: &GroupAffine<Parameters>,
    ) -> Result<(), &'static str>;

    /// Append a prover `Vec` of `point` with the given `label` if it's not an identity/zero element.
    fn validate_and_append_points_vector(
        &mut self,
        label: &'static [u8],
        points: &Vec<GroupAffine<Parameters>>,
    ) -> Result<(), &'static str>;

    /// Compute a verifier `label`ed challenge variable.
    fn challenge_scalar(&mut self, label: &'static [u8]) -> ScalarField;
}

impl TranscriptProtocol for Transcript {
    fn append_scalar(&mut self, label: &'static [u8], scalar: &ScalarField) {
        let mut bytes = Vec::new();
        scalar.serialize(&mut bytes).unwrap();
        self.append_message(label, &bytes[..]);
    }

    fn append_point(
        &mut self,
        label: &'static [u8],
        point: &GroupAffine<Parameters>,
    ) -> Result<(), &'static str> {
        let mut bytes = Vec::new();
        let write_result = point.write(&mut bytes);
        if write_result.is_ok() {
            self.append_message(label, &bytes[..]);
            return Ok(());
        } else {
            return Err("Point append error");
        }
    }

    fn domain_sep(&mut self, label: &'static [u8]) {
        self.append_message(b"dom-sep", label);
    }

    fn challenge_scalar(&mut self, label: &'static [u8]) -> ScalarField {
        let mut buf = [0; 64];
        self.challenge_bytes(label, &mut buf);
        return ScalarField::from_le_bytes_mod_order(&buf);
    }

    fn validate_and_append_point(
        &mut self,
        label: &'static [u8],
        point: &GroupAffine<Parameters>,
    ) -> Result<(), &'static str> {
        if point.is_zero() {
            return Err("Point validation failed.");
        } else {
            let result = self.append_point(label, &point);
            if result.is_err() {
                return Err("Point validation failed.");
            } else {
                return Ok(());
            }
        }
    }

    fn append_points_vector(
        &mut self,
        label: &'static [u8],
        points: &Vec<GroupAffine<Parameters>>,
    ) -> Result<(), &'static str> {
        for (point) in points.iter() {
            let result = self.append_point(label, &point);
            if result.is_err() {
                return result;
            }
        }
        return Ok(());
    }

    fn validate_and_append_points_vector(
        &mut self,
        label: &'static [u8],
        points: &Vec<GroupAffine<Parameters>>,
    ) -> Result<(), &'static str> {
        for (point) in points.iter() {
            let result = self.validate_and_append_point(label, &point);
            if result.is_err() {
                return result;
            }
        }
        return Ok(());
    }
}
