use crate::sigma_ab::sigma_ab_proof::Proof;
use crate::transcript::TranscriptProtocol;
use crate::utils::Utils;
use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, PrimeField, Zero};
use ark_std::rand::Rng;
use merlin::Transcript;

pub struct Prover<'a> {
    transcript: &'a mut Transcript,
    /// public generator
    g: &'a G1Point,
    d: &'a G1Point,
    c_r: &'a G1Point,
    b: usize,
    a: &'a Vec<usize>,
    sk: &'a ScalarField,
}

impl<'a> Prover<'a> {
    pub fn new(
        transcript: &'a mut Transcript,
        g: &'a G1Point,
        d: &'a G1Point,
        c_r: &'a G1Point,
        b: usize,
        a: &'a Vec<usize>,
        sk: &'a ScalarField,
    ) -> Self {
        transcript.domain_sep(b"SigmaAB");

        Prover {
            transcript,
            g,
            d,
            c_r,
            b,
            a,
            sk,
        }
    }

    pub fn generate_proof<R: Rng>(&mut self, rng: &mut R) -> Proof {
        let k_sk: ScalarField = Utils::get_n_random_scalars(1, rng)[0];
        let k_ab: ScalarField = Utils::get_n_random_scalars(1, rng)[0];

        let z: ScalarField = self.transcript.challenge_scalar(b"z");

        let sum_d_z: G1Point = (1..=self.a.len())
            .map(|i| self.d.mul(z.pow([2 + (i as u64)])).into_affine())
            .sum::<G1Point>();

        let c_r_d_z: G1Point = (self.c_r.into_projective()
            - self.d.mul(ScalarField::from(self.a.len() as i128)))
        .into_affine()
        .mul(z.pow([2]).into_repr())
        .into_affine();

        let a_ab: G1Point = (c_r_d_z + sum_d_z).mul(k_sk.into_repr()).into_affine()
            + self.g.mul(k_ab.into_repr()).into_affine();

        self.transcript.append_point(b"A_ab", &a_ab);

        let c: ScalarField = self.transcript.challenge_scalar(b"c");

        let s_ab: ScalarField = self.get_s_ab(&k_ab, &c, self.b, &z, self.a);

        let s_sk: ScalarField = (*self.sk * c) + k_sk;

        self.transcript.append_scalar(b"s_ab", &s_ab);
        self.transcript.append_scalar(b"s_sk", &s_sk);

        Proof::new(a_ab, s_sk, s_ab)
    }

    fn get_s_ab(
        &mut self,
        k_ab: &ScalarField,
        c: &ScalarField,
        b: usize,
        z: &ScalarField,
        a: &Vec<usize>,
    ) -> ScalarField {
        let n: usize = a.len();
        let sum_a_z: ScalarField = (1..=n)
            .map(|i: usize| ScalarField::from(a[i - 1] as i64) * z.pow([2 + (i as u64)]))
            .sum();

        let right: ScalarField = ((ScalarField::from(b as i64)) * z.pow([2])) + sum_a_z;

        *k_ab + (*c * right)
    }
}
