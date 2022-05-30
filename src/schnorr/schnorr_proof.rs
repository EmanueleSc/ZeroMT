use ark_bn254::{g1::Parameters, Fr as ScalarField};
use ark_ec::short_weierstrass_jacobian::GroupAffine;

#[derive(Debug)]
pub struct SchnorrProof {
    a: GroupAffine<Parameters>,
    z: ScalarField,
}

#[derive(Debug)]
pub enum SchnorrProofError {
    /// This error occurs when a proof failed to verify.
    #[cfg_attr(feature = "std", error("Proof verification failed."))]
    ProofVerificationError,
}

impl SchnorrProof {
    pub fn new(a: GroupAffine<Parameters>, z: ScalarField) -> Self {
        return SchnorrProof { a, z };
    }

    pub fn get_a(&self) -> &GroupAffine<Parameters> {
        return &self.a;
    }

    pub fn get_z(&self) -> &ScalarField {
        return &self.z;
    }
}
