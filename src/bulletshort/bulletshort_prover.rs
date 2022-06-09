use crate::transcript::TranscriptProtocol;
use crate::proof_utils::ProofUtils;
use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, One, PrimeField, Zero};
use ark_std::rand::Rng;
use merlin::Transcript;
use ark_crypto_primitives::crh::pedersen;

use super::poly::PolyVector;

pub struct Prover<'a> {
    transcript: &'a mut Transcript,
    // public generator
    //g: &'a G1Point,
    //h: &'a G1Point,
    // sender balance
    //b: usize,
    // recipients amounts
    //a: &'a Vec<usize>,
}

impl<'a> Prover<'a> {
    pub fn new(
        transcript: &'a mut Transcript,
        //g: &'a G1Point,
        //h: &'a G1Point,
        //b: usize,
        //a: &'a Vec<usize>,
    ) -> Self {
        transcript.domain_sep(b"Bulletshort");
        Prover {
            transcript,
            //g,
            //h,
            //b,
            //a,
        }
    }

    pub fn generate_proof<R: Rng>(&mut self, rng: &mut R) /* -> Proof */ {
        let n: usize = 8;       // 8 bits values
        let m = 2 * n;   // 2 values, 16 bits in total

        let b1: u8 = 1;         // first value
        let b2: u8 = 2;         // second value

        let alpha = ProofUtils::get_n_random_scalars(1, rng)[0];
        let rho = ProofUtils::get_n_random_scalars(1, rng)[0];

        let a_l = Self::get_a_l(b1, b2);
        let a_r = Self::get_a_r(&a_l);


        let s_l: Vec<ScalarField> = ProofUtils::get_n_random_scalars(m, rng);
        let s_r: Vec<ScalarField> = ProofUtils::get_n_random_scalars(m, rng);

        /*
        let g_vec: Vec<G1Point> = Utils::get_n_generators_berkeley(Utils::get_n_by_m(m), rng);
        let h_vec: Vec<G1Point> = Utils::get_n_generators_berkeley(Utils::get_n_by_m(m), rng);

        let a_commitment: G1Point =
            Utils::pedersen_vector_commitment(&alpha, self.h, &a_l, &g_vec, &a_r, &h_vec).unwrap();

        let s_commitment: G1Point =
            Utils::pedersen_vector_commitment(&rho, &self.h, &s_l, &g_vec, &s_r, &h_vec).unwrap();

        self.transcript.append_point(b"A", &a_commitment);
        self.transcript.append_point(b"S", &s_commitment);
        */

        //const lPoly = new FieldVectorPolynomial(aL.plus(z.redNeg()), sL);
        //const rPoly = new FieldVectorPolynomial(ys.hadamard(aR.plus(z)).add(twoTimesZs), sR.hadamard(ys));
        //const tPolyCoefficients = lPoly.innerProduct(rPoly); // just an array of BN Reds... should be length 3
        
        // TEST: mock prover challanges - REPLACE WITH: y: ScalarField = self.transcript.challenge_scalar(b"y")
        let y: ScalarField = ProofUtils::get_n_random_scalars(1, rng)[0];
        let z: ScalarField = ProofUtils::get_n_random_scalars(1, rng)[0];

        let ones = Self::generate_scalar_exp_vector(
            m,
            &ScalarField::from(1)
        );
        let mut zs = Vec::with_capacity(m);
        zs = (0..m).map(|i| z * ones[i]).collect();

        let a_l_diff_zs = Self::subtract_scalar_scalar(
            &a_l, 
            &zs
        ).unwrap();
        let left_poly = PolyVector::new(&vec![a_l_diff_zs, s_l]);

        /*

        let l: PolyVector = Self::get_l_poly_vec(&z, &a_l, &s_l);
        let r: PolyVector = Self::get_r_poly_vec(m, n, &y, &z, &a_r, &s_r);

        let t: PolyCoefficients = PolyCoefficients::new(&l, &r);

        let tau_1: ScalarField = Utils::get_n_random_scalars(1, rng)[0];
        let tau_2: ScalarField = Utils::get_n_random_scalars(1, rng)[0];

        let t_commitment_1: G1Point =
            Utils::pedersen_commitment(t.get_t_1(), self.g, &tau_1, self.h);

        let t_commitment_2: G1Point =
            Utils::pedersen_commitment(t.get_t_2(), self.g, &tau_2, self.h);

        self.transcript.append_point(b"T1", &t_commitment_1);
        self.transcript.append_point(b"T2", &t_commitment_2);

        let x: ScalarField = self.transcript.challenge_scalar(b"x");

        let l_poly_vec: Vec<ScalarField> = l.evaluate(&x);
        let r_poly_vec: Vec<ScalarField> = r.evaluate(&x);

        let t_hat: ScalarField =
            Utils::inner_product_scalar_scalar(&l_poly_vec, &r_poly_vec).unwrap();

        // let t_x: ScalarField = t.evaluate(&x);
        // println!("Check {:?}", t_hat == t_x);

        // Theoretical doubt
        let tau_x: ScalarField = x * (tau_1 + (x * tau_2));

        let mu: ScalarField = alpha + rho * x;

        let k_ab: ScalarField = Utils::get_n_random_scalars(1, rng)[0];
        let k_tau: ScalarField = Utils::get_n_random_scalars(1, rng)[0];

        let a_t_commitment: G1Point = Utils::pedersen_commitment(&(-k_ab), self.g, &k_tau, self.h);

        self.transcript.append_scalar(b"t_hat", &t_hat);
        self.transcript.append_scalar(b"mu", &mu);
        self.transcript.append_point(b"A_t", &a_t_commitment);

        let c: ScalarField = self.transcript.challenge_scalar(b"c");

        let s_ab: ScalarField = Self::get_s_ab(&k_ab, &c, self.b, &z, self.a);
        let s_tau: ScalarField = (tau_x * c) + k_tau;

        self.transcript.append_scalar(b"s_ab", &s_ab);
        self.transcript.append_scalar(b"s_tau", &s_tau);

        Proof::new(
            a_commitment,
            s_commitment,
            t_commitment_1,
            t_commitment_2,
            t_hat,
            mu,
            a_t_commitment,
            s_ab,
            s_tau,
        ) */
    }

    /*fn get_s_ab(
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

        let right: ScalarField = (ScalarField::from(b as i64) * z.pow([2])) + sum_a_z;

        *k_ab + (*c * right)
    }*/

    /*fn generate_zero_two_zero_vec(m: usize, n: usize, j: usize) -> Vec<ScalarField> {
        let mut to_return: Vec<ScalarField> = Vec::<ScalarField>::with_capacity(m * n);

        to_return.append(&mut Utils::generate_scalar_exp_vector(
            (j - 1) * n,
            &ScalarField::zero(),
        ));

        to_return.append(&mut Utils::generate_scalar_exp_vector(
            n,
            &ScalarField::from(2),
        ));
        to_return.append(&mut Utils::generate_scalar_exp_vector(
            (m - j) * n,
            &ScalarField::zero(),
        ));

        return to_return;
    }*/

    pub fn get_a_l(b1: u8, b2: u8) -> Vec<ScalarField> {
        let bytes = vec![b1, b2];
        let bits = Self::concat_bytes_to_bits(&bytes);
        bits.iter().map(|bit| ScalarField::from(*bit)).collect()
    }

    pub fn get_a_r(a_l: &Vec<ScalarField>) -> Vec<ScalarField> {
        a_l.iter().map(|bit| *bit - ScalarField::one()).collect()
    }

    pub fn concat_bytes_to_bits(bytes: &[u8]) -> Vec<u8> {
        pedersen::bytes_to_bits(bytes)
            .iter()
            .map(|bit| *bit as u8)
            .collect()
    }

    pub fn generate_scalar_exp_vector(n: usize, s: &ScalarField) -> Vec<ScalarField> {
        (0..n).map(|i: usize| s.pow([i as u64])).collect()
    }

    pub fn inner_product_scalar_scalar(
        vec_1: &Vec<ScalarField>,
        vec_2: &Vec<ScalarField>,
    ) -> Result<ScalarField, String> {
        if vec_1.len() != vec_2.len() {
            return Err(String::from("Inner product fail"));
        }

        Ok(Self::hadamard_product_scalar_scalar(vec_1, vec_2)
            .unwrap()
            .iter()
            .sum()
        )
    }

    pub fn hadamard_product_scalar_scalar(
        vec_1: &Vec<ScalarField>,
        vec_2: &Vec<ScalarField>,
    ) -> Result<Vec<ScalarField>, String> {
        if vec_1.len() != vec_2.len() {
            return Err(String::from("Hadamard vectors have not equal len"));
        }

        Ok(vec_1
            .iter()
            .zip(vec_2.iter())
            .map(|(s1, s2)| *s1 * *s2)
            .collect()
        )
    }

    pub fn sum_scalar_scalar(
        vec_1: &Vec<ScalarField>,
        vec_2: &Vec<ScalarField>,
    ) -> Result<Vec<ScalarField>, String> {
        if vec_1.len() != vec_2.len() {
            return Err(String::from("Sum vectors have not equal len"));
        }

        Ok(vec_1
            .iter()
            .zip(vec_2.iter())
            .map(|(s1, s2)| *s1 + *s2)
            .collect())
    }

    pub fn subtract_scalar_scalar(
        vec_1: &Vec<ScalarField>,
        vec_2: &Vec<ScalarField>,
    ) -> Result<Vec<ScalarField>, String> {
        if vec_1.len() != vec_2.len() {
            return Err(String::from("Subtract vectors have not equal len"));
        }

        Ok(vec_1
            .iter()
            .zip(vec_2.iter())
            .map(|(s1, s2)| *s1 - *s2)
            .collect())
    }

    /*
    pub fn number_to_be_bits_reversed(number: usize) -> Vec<u8> {
        let bits: Vec<u8> = (0..Self::get_n())
            .map(|i| (((number >> i) & 1) as u8))
            .collect();
        return bits;
    }
    */

    /*fn get_y_vec(m: usize, n: usize, y: &ScalarField) -> Vec<ScalarField> {
        Utils::generate_scalar_exp_vector(m * n, y)
    }*/

    /* fn get_z_vec(m: usize, n: usize, z: &ScalarField) -> Vec<ScalarField> {
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
    } */

    /* fn get_l_poly_vec(
        z: &ScalarField,
        a_l: &Vec<ScalarField>,
        s_l: &Vec<ScalarField>,
    ) -> PolyVector {
        let l_vec_left: Vec<ScalarField> = Utils::subtract_scalar(&z, &a_l);
        let l_vec_right: Vec<ScalarField> = Utils::product_scalar(&ScalarField::one(), &s_l);

        PolyVector::new(l_vec_left, l_vec_right)
    } */

    /* fn get_r_poly_vec(
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
    } */
}