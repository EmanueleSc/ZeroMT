use crate::transcript::TranscriptProtocol;
use crate::utils::Utils;
use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
use ark_ff::{Field, One, Zero};
use ark_std::rand::Rng;
use merlin::Transcript;

use super::{
    poly_coefficients::PolyCoefficients, poly_vector::PolyVector, range_proof::RangeProof,
};

pub struct RangeProver<'a> {
    transcript: &'a mut Transcript,
    /// public generator
    g: &'a G1Point,
    h: &'a G1Point,
    remaining_balance: usize,
    amounts: &'a Vec<usize>,
    g_vec: &'a Vec<G1Point>,
    h_vec: &'a Vec<G1Point>,
    n: usize,
}

impl<'a> RangeProver<'a> {
    pub fn new(
        transcript: &'a mut Transcript,
        g: &'a G1Point,
        h: &'a G1Point,
        remaining_balance: usize,
        amounts: &'a Vec<usize>,
        g_vec: &'a Vec<G1Point>,
        h_vec: &'a Vec<G1Point>,
        n: usize,
    ) -> Self {
        transcript.domain_sep(b"RangeProof");
        RangeProver {
            transcript,
            g,
            h,
            remaining_balance,
            amounts,
            g_vec,
            h_vec,
            n,
        }
    }

    pub fn generate_proof<R: Rng>(
        &mut self,
        rng: &mut R,
    ) -> (
        RangeProof,
        ScalarField,
        Vec<ScalarField>,
        Vec<ScalarField>,
        ScalarField,
        ScalarField,
        ScalarField,
    ) {
        let m: usize = self.amounts.len() + 1;

        let alpha: ScalarField = Utils::get_n_random_scalars(1, rng)[0];
        let rho: ScalarField = Utils::get_n_random_scalars(1, rng)[0];

        let a_l: Vec<ScalarField> = self.get_a_l(self.remaining_balance, self.amounts, m, self.n);
        let a_r: Vec<ScalarField> = self.get_a_r(&a_l);

        let s_l: Vec<ScalarField> = Utils::get_n_random_scalars(m * self.n, rng);
        let s_r: Vec<ScalarField> = Utils::get_n_random_scalars(m * self.n, rng);

        let a_commitment: G1Point =
            Utils::pedersen_vector_commitment(&alpha, self.h, &a_l, self.g_vec, &a_r, self.h_vec)
                .unwrap();

        let s_commitment: G1Point =
            Utils::pedersen_vector_commitment(&rho, &self.h, &s_l, self.g_vec, &s_r, self.h_vec)
                .unwrap();

        let _result = self.transcript.append_point(b"A", &a_commitment);
        let _result = self.transcript.append_point(b"S", &s_commitment);

        let y: ScalarField = self.transcript.challenge_scalar(b"y");
        let z: ScalarField = self.transcript.challenge_scalar(b"z");

        let l: PolyVector = self.get_l_poly_vec(&z, &a_l, &s_l);
        let r: PolyVector = self.get_r_poly_vec(m, self.n, &y, &z, &a_r, &s_r);

        let t: PolyCoefficients = PolyCoefficients::new(&l, &r);

        let tau_1: ScalarField = Utils::get_n_random_scalars(1, rng)[0];
        let tau_2: ScalarField = Utils::get_n_random_scalars(1, rng)[0];

        let t_commitment_1: G1Point =
            Utils::pedersen_commitment(t.get_t_1(), self.g, &tau_1, self.h);

        let t_commitment_2: G1Point =
            Utils::pedersen_commitment(t.get_t_2(), self.g, &tau_2, self.h);

        let _result = self.transcript.append_point(b"T1", &t_commitment_1);
        let _result = self.transcript.append_point(b"T2", &t_commitment_2);

        let x: ScalarField = self.transcript.challenge_scalar(b"x");

        let l_poly_vec: Vec<ScalarField> = l.evaluate(&x);
        let r_poly_vec: Vec<ScalarField> = r.evaluate(&x);

        let t_hat: ScalarField =
            Utils::inner_product_scalar_scalar(&l_poly_vec, &r_poly_vec).unwrap();

        let tau_x: ScalarField = (x * tau_1) + (x * x * tau_2);

        let mu: ScalarField = alpha + rho * x;

        let k_ab: ScalarField = Utils::get_n_random_scalars(1, rng)[0];
        let k_tau: ScalarField = Utils::get_n_random_scalars(1, rng)[0];

        let a_t_commitment: G1Point = Utils::pedersen_commitment(&(-k_ab), self.g, &k_tau, self.h);

        let _result = self.transcript.append_scalar(b"t_hat", &t_hat);
        let _result = self.transcript.append_scalar(b"mu", &mu);
        let _result = self.transcript.append_point(b"A_t", &a_t_commitment);

        let c: ScalarField = self.transcript.challenge_scalar(b"c");

        let s_ab: ScalarField = self.get_s_ab(&k_ab, &c, self.remaining_balance, &z, self.amounts);
        let s_tau: ScalarField = (tau_x * c) + k_tau;

        let _result = self.transcript.append_scalar(b"s_ab", &s_ab);
        let _result = self.transcript.append_scalar(b"s_tau", &s_tau);

        (
            RangeProof::new(
                a_commitment,
                s_commitment,
                t_commitment_1,
                t_commitment_2,
                t_hat,
                mu,
                a_t_commitment,
                s_ab,
                s_tau,
            ),
            t_hat,
            l_poly_vec,
            r_poly_vec,
            x,
            y,
            z,
        )
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
            .map(|i: usize| ScalarField::from(a[i - 1] as i128) * z.pow([2 + (i as u64)]))
            .sum();

        let right: ScalarField = (ScalarField::from(b as i128) * z.pow([2])) + sum_a_z;

        *k_ab + (*c * right)
    }

    fn generate_zero_two_zero_vec(&mut self, m: usize, n: usize, j: usize) -> Vec<ScalarField> {
        let mut to_return: Vec<ScalarField> = Vec::<ScalarField>::with_capacity(m * n);

        to_return.append(&mut (0..((j - 1) * n)).map(|_| ScalarField::zero()).collect());

        to_return.append(&mut Utils::generate_scalar_exp_vector(
            n,
            &ScalarField::from(2),
        ));

        to_return.append(&mut (0..((m - j) * n)).map(|_| ScalarField::zero()).collect());

        return to_return;
    }

    fn get_a_l(
        &mut self,
        balance: usize,
        amounts: &Vec<usize>,
        m: usize,
        n: usize,
    ) -> Vec<ScalarField> {
        let mut bits: Vec<u8> = Vec::<u8>::with_capacity(m * n);
        Utils::number_to_be_bits_reversed(balance, n)
            .iter()
            .for_each(|bit| bits.push(*bit));

        amounts
            .iter()
            .map(|amount| Utils::number_to_be_bits_reversed(*amount, n))
            .for_each(|bit_array| {
                bit_array.iter().for_each(|bit| bits.push(*bit));
            });

        return bits.iter().map(|bit| ScalarField::from(*bit)).collect();
    }

    fn get_a_r(&mut self, a_l: &Vec<ScalarField>) -> Vec<ScalarField> {
        return a_l.iter().map(|bit| *bit - ScalarField::one()).collect();
    }

    fn get_y_vec(&mut self, m: usize, n: usize, y: &ScalarField) -> Vec<ScalarField> {
        Utils::generate_scalar_exp_vector(m * n, y)
    }

    fn get_z_vec(&mut self, m: usize, n: usize, z: &ScalarField) -> Vec<ScalarField> {
        (1..=m)
            .map(|j: usize| {
                Utils::product_scalar(
                    &z.pow([(1 + j) as u64]),
                    &self.generate_zero_two_zero_vec(m, n, j),
                )
            })
            .reduce(|accum: Vec<ScalarField>, item: Vec<ScalarField>| {
                Utils::sum_scalar_scalar(&accum, &item).unwrap()
            })
            .unwrap()
    }

    fn get_l_poly_vec(
        &mut self,
        z: &ScalarField,
        a_l: &Vec<ScalarField>,
        s_l: &Vec<ScalarField>,
    ) -> PolyVector {
        let l_vec_left: Vec<ScalarField> = Utils::subtract_scalar(&z, &a_l);
        let l_vec_right: Vec<ScalarField> = Utils::product_scalar(&ScalarField::one(), &s_l);

        PolyVector::new(l_vec_left, l_vec_right)
    }

    fn get_r_poly_vec(
        &mut self,
        m: usize,
        n: usize,
        y: &ScalarField,
        z: &ScalarField,
        a_r: &Vec<ScalarField>,
        s_r: &Vec<ScalarField>,
    ) -> PolyVector {
        let y_vec: Vec<ScalarField> = self.get_y_vec(m, n, &y);
        let z_vec: Vec<ScalarField> = self.get_z_vec(m, n, &z);

        let r_vec_left_hadamard: Vec<ScalarField> =
            Utils::hadamard_product_scalar_scalar(&y_vec, &Utils::sum_scalar(&z, &a_r)).unwrap();

        let r_vec_left: Vec<ScalarField> =
            Utils::sum_scalar_scalar(&r_vec_left_hadamard, &z_vec).unwrap();

        let r_vec_right: Vec<ScalarField> =
            Utils::hadamard_product_scalar_scalar(&y_vec, &s_r).unwrap();

        PolyVector::new(r_vec_left, r_vec_right)
    }
}
