use crate::{
    InnerProof, InnerProver, RangeProof, RangeProver, SigmaABProof, SigmaABProver, SigmaRProof,
    SigmaRProver, SigmaSKProof, SigmaSKProver, SigmaYProof, SigmaYProver, TranscriptProtocol,
    Utils, ZeroMTProof,
};
use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, One, PrimeField};
use merlin::Transcript;
use rand::Rng;

pub struct ZeroMTProver<'a> {
    transcript: &'a mut Transcript,
    g: &'a G1Point,
    h: &'a G1Point,
    remaining_balance: usize,
    amounts: &'a Vec<usize>,
    g_vec: &'a Vec<G1Point>,
    h_vec: &'a Vec<G1Point>,
    u: &'a G1Point,
    m: usize,
    n: usize,
    d: &'a G1Point,
    c_r: &'a G1Point,
    sk: &'a ScalarField,
    r: &'a ScalarField,
    y: &'a G1Point,
    y_bar: &'a Vec<G1Point>,
}

impl<'a> ZeroMTProver<'a> {
    pub fn new(
        transcript: &'a mut Transcript,
        g: &'a G1Point,
        h: &'a G1Point,
        remaining_balance: usize,
        amounts: &'a Vec<usize>,
        g_vec: &'a Vec<G1Point>,
        h_vec: &'a Vec<G1Point>,
        u: &'a G1Point,
        m: usize,
        n: usize,
        d: &'a G1Point,
        c_r: &'a G1Point,
        sk: &'a ScalarField,
        r: &'a ScalarField,
        y: &'a G1Point,
        y_bar: &'a Vec<G1Point>,
    ) -> Self {
        transcript.domain_sep(b"ZeroMTProof");
        ZeroMTProver {
            transcript,
            g,
            h,
            remaining_balance,
            amounts,
            g_vec,
            h_vec,
            u,
            m,
            n,
            d,
            c_r,
            sk,
            r,
            y,
            y_bar,
        }
    }

    pub fn generate_proof<R: Rng>(&mut self, rng: &mut R) -> ZeroMTProof {
        let (range_proof, t_hat, l_poly_vec, r_poly_vec, x, y, z): (
            RangeProof,
            ScalarField,
            Vec<ScalarField>,
            Vec<ScalarField>,
            ScalarField,
            ScalarField,
            ScalarField,
        ) = RangeProver::new(
            self.transcript,
            self.g,
            self.h,
            self.remaining_balance,
            self.amounts,
            self.g_vec,
            self.h_vec,
            self.n,
        )
        .generate_proof(rng);

        let (u, h_first_vec, phu) = Self::get_inner_arguments(
            self.m,
            self.n,
            &x,
            &y,
            &z,
            range_proof.get_a(),
            range_proof.get_s(),
            self.h,
            self.g_vec,
            self.h_vec,
            self.u,
            range_proof.get_mu(),
        );

        let inner_proof: InnerProof = InnerProver::new(
            self.transcript,
            self.g_vec,
            &h_first_vec,
            &phu,
            &t_hat,
            &l_poly_vec,
            &r_poly_vec,
            &u,
        )
        .generate_proof();

        let sigma_ab_proof: SigmaABProof = SigmaABProver::new(
            self.transcript,
            self.g,
            self.d,
            self.c_r,
            self.remaining_balance,
            self.amounts,
            self.sk,
        )
        .generate_proof(rng);

        let sigma_y_proof: SigmaYProof =
            SigmaYProver::new(self.transcript, self.r, self.y, self.y_bar).generate_proof(rng);

        let sigma_sk_proof: SigmaSKProof =
            SigmaSKProver::new(self.transcript, self.g, self.sk).generate_proof(rng);

        let sigma_r_proof: SigmaRProof =
            SigmaRProver::new(self.transcript, self.g, self.r).generate_proof(rng);

        ZeroMTProof::new(
            range_proof,
            inner_proof,
            sigma_ab_proof,
            sigma_r_proof,
            sigma_sk_proof,
            sigma_y_proof,
        )
    }

    fn get_inner_arguments(
        m: usize,
        n: usize,
        x: &ScalarField,
        y: &ScalarField,
        z: &ScalarField,
        a: &G1Point,
        s: &G1Point,
        h: &G1Point,
        g_vec: &Vec<G1Point>,
        h_vec: &Vec<G1Point>,
        u: &G1Point,
        mu: &ScalarField,
    ) -> (G1Point, Vec<G1Point>, G1Point) {
        let h_first_vec: Vec<G1Point> = (0..m * n)
            .map(|i: usize| {
                h_vec[i]
                    .mul(y.pow([(i as u64)]).inverse().unwrap().into_repr())
                    .into_affine()
            })
            .collect();

        let p: G1Point = *a
            + s.mul(x.into_repr()).into_affine()
            + -Utils::inner_product_point_scalar(
                &g_vec,
                &Utils::generate_scalar_exp_vector(m * n, &ScalarField::one()),
            )
            .unwrap()
            .mul((z).into_repr())
            .into_affine()
            + Utils::inner_product_point_scalar(
                &h_first_vec,
                &Utils::generate_scalar_exp_vector(m * n, &y),
            )
            .unwrap()
            .mul((z).into_repr())
            .into_affine()
            + (1..=m)
                .map(|j: usize| {
                    Utils::inner_product_point_scalar(
                        &h_first_vec[((j - 1) * n)..(j * n)].to_vec(),
                        &Utils::generate_scalar_exp_vector(n, &ScalarField::from(2)),
                    )
                    .unwrap()
                    .mul((z.pow([1 + (j as u64)])).into_repr())
                    .into_affine()
                })
                .sum::<G1Point>();
        let phu: G1Point = p + -h.mul(mu.into_repr()).into_affine();

        (*u, h_first_vec, phu)
    }
}
