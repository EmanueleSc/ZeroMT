use crate::transcript::TranscriptProtocol;
use crate::utils::Utils;
use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, One, PrimeField, Zero};
use ark_std::rand::Rng;
use merlin::Transcript;

use super::{
    bulletproofs_proof::Proof, poly_coefficients::PolyCoefficients, poly_vector::PolyVector,
};

pub struct Prover<'a> {
    transcript: &'a mut Transcript,
    /// public generator
    g: &'a G1Point,
    /// sender balance
    b: usize,
    /// recipients amounts
    a: &'a Vec<usize>,
}

impl<'a> Prover<'a> {
    pub fn new(
        transcript: &'a mut Transcript,
        g: &'a G1Point,
        b: usize,
        a: &'a Vec<usize>,
    ) -> Self {
        transcript.domain_sep(b"Bulletproofs");
        Prover {
            transcript,
            g,
            b,
            a,
        }
    }

    pub fn generate_proof<R: Rng>(&mut self, rng: &mut R) -> Proof {
        let n: usize = Utils::get_n();
        let m: usize = self.a.len() + 1;

        let alpha: ScalarField = Utils::get_n_random_scalars(1, rng)[0];
        let rho: ScalarField = Utils::get_n_random_scalars(1, rng)[0];

        let a_l: Vec<ScalarField> = Self::get_a_l(self.b, self.a);
        let a_r: Vec<ScalarField> = Self::get_a_r(&a_l);

        let s_l: Vec<ScalarField> = Utils::get_n_random_scalars(Utils::get_n_by_m(m), rng);
        let s_r: Vec<ScalarField> = Utils::get_n_random_scalars(Utils::get_n_by_m(m), rng);

        let g_vec: Vec<G1Point> = Utils::get_n_generators_berkeley(Utils::get_n_by_m(m), rng);
        let h_vec: Vec<G1Point> = Utils::get_n_generators_berkeley(Utils::get_n_by_m(m), rng);

        let h: G1Point = Utils::get_n_generators_berkeley(1, rng)[0];

        let a_commitment: G1Point =
            Utils::pedersen_vector_commitment(&alpha, &h, &a_l, &g_vec, &a_r, &h_vec).unwrap();

        let s_commitment: G1Point =
            Utils::pedersen_vector_commitment(&rho, &h, &s_l, &g_vec, &s_r, &h_vec).unwrap();

        self.transcript.append_point(b"A", &a_commitment);
        self.transcript.append_point(b"S", &s_commitment);

        let y: ScalarField = self.transcript.challenge_scalar(b"y");
        let z: ScalarField = self.transcript.challenge_scalar(b"z");

        let l_vec: PolyVector = Self::get_l_vec(&z, &a_l, &s_l);
        let r_vec: PolyVector = Self::get_r_vec(m, n, &y, &z, &a_r, &s_r);

        let t_vec: PolyCoefficients = PolyCoefficients::new(&l_vec, &r_vec);

        let tau_1: ScalarField = Utils::get_n_random_scalars(1, rng)[0];
        let tau_2: ScalarField = Utils::get_n_random_scalars(1, rng)[0];

        let t_commitment_1: G1Point =
            Utils::pedersen_commitment(t_vec.get_t_1(), &self.g, &tau_1, &h);
        let t_commitment_2: G1Point =
            Utils::pedersen_commitment(t_vec.get_t_2(), &self.g, &tau_2, &h);

        self.transcript.append_point(b"T1", &t_commitment_1);
        self.transcript.append_point(b"T2", &t_commitment_2);

        let x: ScalarField = self.transcript.challenge_scalar(b"x");

        println!("Prover y - {:?}", y);
        println!("Prover x - {:?}", x);
        println!("Prover z - {:?}", z);

        Proof::new(a_commitment, s_commitment, t_commitment_1, t_commitment_2)
    }

    fn generate_zero_two_zero_vec(m: usize, n: usize, j: usize) -> Vec<ScalarField> {
        let mut to_return: Vec<ScalarField> = Vec::<ScalarField>::with_capacity(m * n);
        let two: ScalarField = ScalarField::from(2);
        for _ in 0..((j - 1) * n) {
            to_return.push(ScalarField::zero());
        }
        for i in 0..n {
            to_return.push(two.pow([i as u64]));
        }
        for _ in 0..((m - j) * n) {
            to_return.push(ScalarField::zero());
        }

        return to_return;
    }
    fn get_a_l(balance: usize, amounts: &Vec<usize>) -> Vec<ScalarField> {
        let mut bits: Vec<u8> = Vec::<u8>::with_capacity(Utils::get_n_by_m(amounts.len() + 1));
        Utils::number_to_be_bits_reversed(balance)
            .iter()
            .for_each(|bit| bits.push(*bit));

        amounts
            .iter()
            .map(|amount| Utils::number_to_be_bits_reversed(*amount))
            .for_each(|bit_array| {
                bit_array.iter().for_each(|bit| bits.push(*bit));
            });

        return bits.iter().map(|bit| ScalarField::from(*bit)).collect();
    }

    fn get_a_r(a_l: &Vec<ScalarField>) -> Vec<ScalarField> {
        return a_l.iter().map(|bit| *bit - ScalarField::one()).collect();
    }

    fn get_y_vec(m: usize, n: usize, y: &ScalarField) -> Vec<ScalarField> {
        (0..m * n).map(|i: usize| y.pow([i as u64])).collect()
    }

    fn get_z_vec(m: usize, n: usize, z: &ScalarField) -> Vec<ScalarField> {
        (1..=m)
            .map(|j: usize| {
                Utils::product_scalar(
                    &z.pow([(1 + j) as u64]),
                    &Self::generate_zero_two_zero_vec(m, n, j),
                )
            })
            .reduce(|accum: Vec<ScalarField>, item: Vec<ScalarField>| {
                Utils::sum_scalar_scalar(&accum, &item).unwrap()
            })
            .unwrap()
    }

    fn get_l_vec(z: &ScalarField, a_l: &Vec<ScalarField>, s_l: &Vec<ScalarField>) -> PolyVector {
        let l_vec_left: Vec<ScalarField> = Utils::subtract_scalar(&z, &a_l);
        let l_vec_right: Vec<ScalarField> = Utils::product_scalar(&ScalarField::one(), &s_l);

        PolyVector::new(l_vec_left, l_vec_right)
    }

    fn get_r_vec(
        m: usize,
        n: usize,
        y: &ScalarField,
        z: &ScalarField,
        a_r: &Vec<ScalarField>,
        s_r: &Vec<ScalarField>,
    ) -> PolyVector {
        let y_vec: Vec<ScalarField> = Self::get_y_vec(m, n, &y);
        let z_vec: Vec<ScalarField> = Self::get_z_vec(m, n, &z);

        let r_vec_left_hadamard: Vec<ScalarField> =
            Utils::hadamard_product_scalar_scalar(&y_vec, &Utils::sum_scalar(&z, &a_r)).unwrap();

        let r_vec_left: Vec<ScalarField> =
            Utils::sum_scalar_scalar(&r_vec_left_hadamard, &z_vec).unwrap();

        let r_vec_right: Vec<ScalarField> =
            Utils::hadamard_product_scalar_scalar(&y_vec, &s_r).unwrap();

        PolyVector::new(r_vec_left, r_vec_right)
    }
}

/*#[test]
pub fn get_a_l_test() {
    let test_balance: usize = 42;
    let test_amounts: Vec<usize> = [1, 2, 3, 4, 5].to_vec();

    let mut test_a_l: Vec<i8> = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        1, 0, 1, 0, 1, 0,
    ]
    .to_vec();
    let mut one_bits = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 1,
    ]
    .to_vec();
    let mut two_bits = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 1, 0,
    ]
    .to_vec();
    let mut three_bits = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 1, 1,
    ]
    .to_vec();
    let mut four_bits = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 1, 0, 0,
    ]
    .to_vec();
    let mut five_bits = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 1, 0, 1,
    ]
    .to_vec();

    test_a_l.reverse();
    one_bits.reverse();
    two_bits.reverse();
    three_bits.reverse();
    four_bits.reverse();
    five_bits.reverse();

    test_a_l.extend(one_bits);
    test_a_l.extend(two_bits);
    test_a_l.extend(three_bits);
    test_a_l.extend(four_bits);
    test_a_l.extend(five_bits);

    let test_a_l_scalar: Vec<ScalarField> =
        test_a_l.iter().map(|bit| ScalarField::from(*bit)).collect();
    let result_a_l: Vec<ScalarField> = Utils::get_a_l(test_balance, &test_amounts);

    assert_eq!(result_a_l, test_a_l_scalar);
}*/

/*#[test]
pub fn get_a_r_test() {
    let test_a_l_scalar: Vec<ScalarField> = [1, 0, 1, 1, 0, 0, 0, 0, 1]
        .to_vec()
        .iter()
        .map(|bit| ScalarField::from(*bit))
        .collect();

    let test_a_r_scalar: Vec<ScalarField> = [0, -1, 0, 0, -1, -1, -1, -1, 0]
        .to_vec()
        .iter()
        .map(|bit| ScalarField::from(*bit))
        .collect();

    let result_a_r: Vec<ScalarField> = Utils::get_a_r(&test_a_l_scalar);

    assert_eq!(result_a_r, test_a_r_scalar);
}*/
