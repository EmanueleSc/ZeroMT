use ark_serialize::*;

use crate::{InnerProof, RangeProof, SigmaABProof, SigmaRProof, SigmaSKProof, SigmaYProof};

#[derive(Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct ZeroMTProof {
    range_proof: RangeProof,
    inner_proof: InnerProof,
    sigma_ab_proof: SigmaABProof,
    sigma_r_proof: SigmaRProof,
    sigma_sk_proof: SigmaSKProof,
    sigma_y_proof: SigmaYProof,
}

impl ZeroMTProof {
    pub fn new(
        range_proof: RangeProof,
        inner_proof: InnerProof,
        sigma_ab_proof: SigmaABProof,
        sigma_r_proof: SigmaRProof,
        sigma_sk_proof: SigmaSKProof,
        sigma_y_proof: SigmaYProof,
    ) -> Self {
        ZeroMTProof {
            range_proof,
            inner_proof,
            sigma_ab_proof,
            sigma_r_proof,
            sigma_sk_proof,
            sigma_y_proof,
        }
    }

    pub fn get_range_proof(&self) -> &RangeProof {
        &self.range_proof
    }

    pub fn get_inner_proof(&self) -> &InnerProof {
        &self.inner_proof
    }

    pub fn get_sigma_ab_proof(&self) -> &SigmaABProof {
        &self.sigma_ab_proof
    }

    pub fn get_sigma_r_proof(&self) -> &SigmaRProof {
        &self.sigma_r_proof
    }

    pub fn get_sigma_sk_proof(&self) -> &SigmaSKProof {
        &self.sigma_sk_proof
    }

    pub fn get_sigma_y_proof(&self) -> &SigmaYProof {
        &self.sigma_y_proof
    }
}
