use crate::transcript::TranscriptProtocol;
use crate::utils::Utils;
use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, PrimeField};

use merlin::Transcript;

use super::inner_proof::InnerProof;

pub struct InnerProver<'a> {
    transcript: &'a mut Transcript,
    g_vec: &'a Vec<G1Point>,
    h_vec: &'a Vec<G1Point>,
    p: &'a G1Point,
    c: &'a ScalarField,
    a_vec: &'a Vec<ScalarField>,
    b_vec: &'a Vec<ScalarField>,
    u: &'a G1Point,
}

impl<'a> InnerProver<'a> {
    pub fn new(
        transcript: &'a mut Transcript,
        g_vec: &'a Vec<G1Point>,
        h_vec: &'a Vec<G1Point>,
        p: &'a G1Point,
        c: &'a ScalarField,
        a_vec: &'a Vec<ScalarField>,
        b_vec: &'a Vec<ScalarField>,
        u: &'a G1Point,
    ) -> Self {
        transcript.domain_sep(b"InnerProductArgument");
        InnerProver {
            transcript,
            g_vec,
            h_vec,
            p,
            c,
            a_vec,
            b_vec,
            u,
        }
    }

    pub fn generate_proof(&mut self) -> InnerProof {
        let x: ScalarField = self.transcript.challenge_scalar(b"x");
        let ux: G1Point = self.u.mul((x).into_repr()).into_affine();
        let p_first: G1Point = *self.p + ux.mul((self.c).into_repr()).into_affine();

        self.inner_product_argument(
            self.g_vec, self.h_vec, &ux, &p_first, self.a_vec, self.b_vec,
        )
    }

    fn inner_product_argument(
        &mut self,
        g_vec: &Vec<G1Point>,
        h_vec: &Vec<G1Point>,
        u: &G1Point,
        p: &G1Point,
        a_vec: &Vec<ScalarField>,
        b_vec: &Vec<ScalarField>,
    ) -> InnerProof {
        let n: usize = g_vec.len();
        if n == 1 {
            let a: ScalarField = a_vec[0];
            let b: ScalarField = b_vec[0];
            let _result = self.transcript.append_scalar(b"a", &a);
            let _result = self.transcript.append_scalar(b"b", &b);
            InnerProof::new(a, b, [].to_vec(), [].to_vec())
        } else {
            let n_first = n / 2;

            let a_left: Vec<ScalarField> = a_vec[..n_first].to_vec();
            let a_right: Vec<ScalarField> = a_vec[n_first..].to_vec();
            let b_left: Vec<ScalarField> = b_vec[..n_first].to_vec();
            let b_right: Vec<ScalarField> = b_vec[n_first..].to_vec();

            let g_left: Vec<G1Point> = g_vec[..n_first].to_vec();
            let g_right: Vec<G1Point> = g_vec[n_first..].to_vec();
            let h_left: Vec<G1Point> = h_vec[..n_first].to_vec();
            let h_right: Vec<G1Point> = h_vec[n_first..].to_vec();

            let c_l: ScalarField = Utils::inner_product_scalar_scalar(&a_left, &b_right).unwrap();
            let c_r: ScalarField = Utils::inner_product_scalar_scalar(&a_right, &b_left).unwrap();

            let l: G1Point =
                Utils::pedersen_vector_commitment(&c_l, &u, &a_left, &g_right, &b_right, &h_left)
                    .unwrap();

            let r: G1Point =
                Utils::pedersen_vector_commitment(&c_r, &u, &a_right, &g_left, &b_left, &h_right)
                    .unwrap();

            let mut l_vec: Vec<G1Point> = [l].to_vec();
            let mut r_vec: Vec<G1Point> = [r].to_vec();

            let _result = self.transcript.append_point(b"l", &l);
            let _result = self.transcript.append_point(b"r", &r);
            let x: ScalarField = self.transcript.challenge_scalar(b"x");

            let g_first_left: Vec<G1Point> =
                Utils::product_scalar_point(&x.inverse().unwrap(), &g_left);
            let g_first_right: Vec<G1Point> = Utils::product_scalar_point(&x, &g_right);
            let g_first: Vec<G1Point> =
                Utils::sum_point_point(&g_first_left, &g_first_right).unwrap();

            let h_first_left: Vec<G1Point> = Utils::product_scalar_point(&x, &h_left);
            let h_first_right: Vec<G1Point> =
                Utils::product_scalar_point(&x.inverse().unwrap(), &h_right);
            let h_first: Vec<G1Point> =
                Utils::sum_point_point(&h_first_left, &h_first_right).unwrap();

            let p_first: G1Point = l.mul(x.pow([2]).into_repr()).into_affine()
                + *p
                + r.mul(x.pow([2]).inverse().unwrap().into_repr())
                    .into_affine();

            let a_first_left: Vec<ScalarField> = Utils::product_scalar(&x, &a_left);
            let a_first_right: Vec<ScalarField> =
                Utils::product_scalar(&x.inverse().unwrap(), &a_right);
            let a_first: Vec<ScalarField> =
                Utils::sum_scalar_scalar(&a_first_left, &a_first_right).unwrap();

            let b_first_left: Vec<ScalarField> =
                Utils::product_scalar(&x.inverse().unwrap(), &b_left);
            let b_first_right: Vec<ScalarField> = Utils::product_scalar(&x, &b_right);
            let b_first: Vec<ScalarField> =
                Utils::sum_scalar_scalar(&b_first_left, &b_first_right).unwrap();

            let rec_proof: InnerProof =
                self.inner_product_argument(&g_first, &h_first, u, &p_first, &a_first, &b_first);
            l_vec.append(&mut rec_proof.get_l_vec().clone());
            r_vec.append(&mut rec_proof.get_r_vec().clone());

            InnerProof::new(*rec_proof.get_a(), *rec_proof.get_b(), l_vec, r_vec)
        }
    }
}
