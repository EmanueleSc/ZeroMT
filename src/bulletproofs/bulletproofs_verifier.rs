use crate::errors::proof_error::throw;
use crate::ProofError;
use crate::{transcript::TranscriptProtocol, Utils};
use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, One, PrimeField};
use merlin::Transcript;
use std::io::Error;

use super::bulletproofs_proof::Proof;

pub struct Verifier<'a> {
    transcript: &'a mut Transcript,
    amounts: usize,
    /// public generator
    g: &'a G1Point,
    h: &'a G1Point,
}

impl<'a> Verifier<'a> {
    pub fn new(
        transcript: &'a mut Transcript,
        g: &'a G1Point,
        h: &'a G1Point,
        amounts: usize,
    ) -> Self {
        transcript.domain_sep(b"Bulletproofs");
        Verifier {
            transcript,
            g,
            h,
            amounts,
        }
    }

    pub fn verify_proof(&mut self, proof: &Proof) -> Result<(), Error> {
        let n: usize = Utils::get_n();
        let m: usize = self.amounts + 1;
        //println!("Verifier started, n: {}, m: {}", n, m);

        self.transcript.append_point(b"A", proof.get_a());
        self.transcript.append_point(b"S", proof.get_s());

        let y: ScalarField = self.transcript.challenge_scalar(b"y");
        let z: ScalarField = self.transcript.challenge_scalar(b"z");

        self.transcript.append_point(b"T1", proof.get_t_1());
        self.transcript.append_point(b"T2", proof.get_t_2());

        let x: ScalarField = self.transcript.challenge_scalar(b"x");

        self.transcript.append_scalar(b"t_hat", proof.get_t_hat());
        self.transcript.append_scalar(b"mu", proof.get_mu());
        self.transcript.append_point(b"A_t", proof.get_a_t());

        let c: ScalarField = self.transcript.challenge_scalar(b"c");

        self.transcript.append_scalar(b"s_ab", proof.get_s_ab());
        self.transcript.append_scalar(b"s_tau", proof.get_s_tau());

        /*println!("v, y {:?}", y);
        println!("v, z {:?}", z);
        println!("v, x {:?}", x);
        println!("v, c {:?}", c);*/

        let delta_left: ScalarField = (z - (z * z))
            * Utils::generate_scalar_exp_vector(m * n, &y)
                .iter()
                .sum::<ScalarField>();

        let delta_right: ScalarField = (1..=m)
            .map(|j: usize| {
                z.pow([2 + (j as u64)])
                    * Utils::generate_scalar_exp_vector(n, &ScalarField::from(2))
                        .iter()
                        .sum::<ScalarField>()
            })
            .sum::<ScalarField>();

        let delta_y_z: ScalarField = delta_left - delta_right;

        let g_exp: ScalarField = (c * *proof.get_t_hat()) - (c * delta_y_z) - *proof.get_s_ab();
        let h_exp: ScalarField = *proof.get_s_tau();

        let left_eq: G1Point = Utils::pedersen_commitment(&g_exp, self.g, &h_exp, self.h);

        // (c*x)T1 + (c*x^2)T2
        // T1^(c*x)T2^(c*x^2)
        // (T1^(x)T2^(x^2))^c

        let g_scal: ScalarField = c * x;
        let h_scal: ScalarField = c * x * x;

        let right_eq: G1Point = *proof.get_a_t()
            + Utils::pedersen_commitment(&g_scal, proof.get_t_1(), &h_scal, proof.get_t_2());

        if left_eq == right_eq {
            return Ok(());
        } else {
            return Err(throw(ProofError::ProofValidationError));
        }
    }
}
