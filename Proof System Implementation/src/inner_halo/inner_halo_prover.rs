use crate::transcript::TranscriptProtocol;
use crate::utils::Utils;
use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, PrimeField};

use merlin::Transcript;

use super::inner_halo_proof::InnerHaloProof;

pub struct InnerHaloProver<'a> {
    g_vec: &'a Vec<G1Point>,        // G vector of group elements
    h:  &'a G1Point,                // H single group element (instead of h_vec)
    t: &'a G1Point,                 // T commitment to polynomial t(x) -> t = <t_vec, g_vec> + r * h
    r: &'a ScalarField,             // randomness r to commit T commitment
    t_hat: &'a ScalarField,         // the polynomial t(x)=t_hat (evaluates to t_hat at point x)
    t_vec: &'a Vec<ScalarField>,    // vector of coefficients of t(X)
    b_vec: &'a Vec<ScalarField>,    // use x challange to derive the b_vec = (1,x,x^2,...,x^d)
    u: &'a G1Point,                 // group element become the first verifer challange
}

impl<'a> InnerHaloProver<'a> {
    pub fn new(
        g_vec: &'a Vec<G1Point>,
        h:  &'a G1Point,
        t: &'a G1Point,
        r: &'a ScalarField, 
        t_hat: &'a ScalarField,
        t_vec: &'a Vec<ScalarField>,
        b_vec: &'a Vec<ScalarField>,
        u: &'a G1Point,
    ) -> Self {
        InnerHaloProver {
            g_vec,
            h,
            t,
            r,
            t_hat,
            t_vec,
            b_vec,
            u,
        }
    }

    pub fn generate_proof(&mut self, transcript: &mut Transcript) -> InnerHaloProof {
        transcript.domain_sep(b"InnerProductArgument");
        
        let t_first: G1Point = *self.t + self.u.mul((self.t_hat).into_repr()).into_affine();

        self.inner_product_argument(
            self.g_vec, self.h, self.u, &t_first, self.t_vec, self.b_vec, self.r, transcript
        )
    }

    fn inner_product_argument(
        &mut self,
        g_vec: &Vec<G1Point>,
        h: &G1Point,
        u: &G1Point,
        t_first: &G1Point,
        t_vec: &Vec<ScalarField>,
        b_vec: &Vec<ScalarField>,
        r: &ScalarField,
        transcript: &mut Transcript,
    ) -> InnerHaloProof {
        let mut rng = ark_std::rand::thread_rng();
        let mut l_vec: Vec<G1Point>;
        let mut r_vec: Vec<G1Point>;

        // ========== RAUND 1 ==========
        let t_vec_one: Vec<ScalarField> = t_vec[..2].to_vec();
        let b_vec_one: Vec<ScalarField> = b_vec[..2].to_vec(); 
        let g_vec_one: Vec<G1Point> = g_vec[..2].to_vec();
        
        let rand_l_one: ScalarField = Utils::get_n_random_scalars_not_zero(1, &mut rng)[0];
        let rand_r_one: ScalarField = Utils::get_n_random_scalars_not_zero(1, &mut rng)[0];

        let mut t_lo = t_vec_one[..1].to_vec();
        let mut t_hi = t_vec_one[1..].to_vec();
        
        let mut b_lo = b_vec_one[..1].to_vec();
        let mut b_hi = b_vec_one[1..].to_vec();
        
        let mut g_lo = g_vec_one[..1].to_vec();
        let mut g_hi = g_vec_one[1..].to_vec();
       
        let l_one: G1Point = g_hi[0].mul(t_lo[0].into_repr()).into_affine()
                           + h.mul(rand_l_one.into_repr()).into_affine()
                           + u.mul(t_lo[0] * b_hi[0]).into_affine();

        let r_one: G1Point = g_lo[0].mul(t_hi[0].into_repr()).into_affine()
                           + h.mul(rand_r_one.into_repr()).into_affine()
                           + u.mul(t_hi[0] * b_lo[0]).into_affine();

        l_vec = [l_one].to_vec();
        r_vec = [r_one].to_vec();
        
        // prover sends l and r
        let _result = transcript.append_point(b"l_one", &l_one);
        let _result = transcript.append_point(b"r_one", &r_one);

        // verifier responds with challange m
        let m_one: ScalarField = transcript.challenge_scalar(b"m_one");

        let t_one: ScalarField = t_hi[0] * m_one.inverse().unwrap() + t_lo[0] * m_one;
        let b_one: ScalarField = b_lo[0] * m_one.inverse().unwrap() + b_hi[0] * m_one;
        let g_one: G1Point = g_lo[0].mul(m_one.inverse().unwrap().into_repr()).into_affine()
                           + g_hi[0].mul(m_one.into_repr()).into_affine();

        // ========== ROUND 0 ========== 
        let t_vec_zero: Vec<ScalarField> = vec![t_one, t_vec[2..][0]];
        let b_vec_zero: Vec<ScalarField> = vec![b_one, b_vec[2..][0]];
        let g_vec_zero: Vec<G1Point> = vec![g_one, g_vec[2..][0]];

        let rand_l_zero: ScalarField = Utils::get_n_random_scalars_not_zero(1, &mut rng)[0];
        let rand_r_zero: ScalarField = Utils::get_n_random_scalars_not_zero(1, &mut rng)[0];

        t_lo = t_vec_zero[..1].to_vec();
        t_hi = t_vec_zero[1..].to_vec();
        
        b_lo = b_vec_zero[..1].to_vec();
        b_hi = b_vec_zero[1..].to_vec();
        
        g_lo = g_vec_zero[..1].to_vec();
        g_hi = g_vec_zero[1..].to_vec();
       
        let l_zero: G1Point = g_hi[0].mul(t_lo[0].into_repr()).into_affine()
                           + h.mul(rand_l_zero.into_repr()).into_affine()
                           + u.mul(t_lo[0] * b_hi[0]).into_affine();

        let r_zero: G1Point = g_lo[0].mul(t_hi[0].into_repr()).into_affine()
                           + h.mul(rand_r_zero.into_repr()).into_affine()
                           + u.mul(t_hi[0] * b_lo[0]).into_affine();

        let mut l_zero_vec = [l_zero].to_vec();
        let mut r_zero_vec = [r_zero].to_vec();
        l_vec.append(&mut l_zero_vec);
        r_vec.append(&mut r_zero_vec);

        // prover sends l and r
        let _result = transcript.append_point(b"l_zero", &l_zero);
        let _result = transcript.append_point(b"r_zero", &r_zero);
 
        // verifier responds with challange m
        let m_zero: ScalarField = transcript.challenge_scalar(b"m_zero");

        let t_zero: ScalarField = t_hi[0] * m_zero.inverse().unwrap() + t_lo[0] * m_zero;
        let b_zero: ScalarField = b_lo[0] * m_zero.inverse().unwrap() + b_hi[0] * m_zero;
        let g_zero: G1Point = g_lo[0].mul(m_zero.inverse().unwrap().into_repr()).into_affine()
                            + g_hi[0].mul(m_zero.into_repr()).into_affine();

            

        // SCHNORR PROTOCOL
        let rand_d: ScalarField = Utils::get_n_random_scalars_not_zero(1, &mut rng)[0];
        let rand_s: ScalarField = Utils::get_n_random_scalars_not_zero(1, &mut rng)[0];

        let r_comm: G1Point = (g_zero + u.mul(b_zero.into_repr()).into_affine()).mul(rand_d.into_repr()).into_affine()
                       + h.mul(rand_s.into_repr()).into_affine();
        
        let _result = transcript.append_point(b"R", &r_comm);
        let x: ScalarField = transcript.challenge_scalar(b"x");
        
        let r_first: ScalarField = rand_l_zero * m_zero.pow([2])
                                 + rand_l_one * m_one.pow([2])
                                 + r
                                 + rand_r_zero * m_zero.pow([2]).inverse().unwrap()
                                 + rand_r_one * m_one.pow([2]).inverse().unwrap();

        let z_one: ScalarField = (t_zero * x) + rand_d;
        let z_two: ScalarField = (r_first * x) + rand_s;
        let _result = transcript.append_scalar(b"z_one", &z_one);
        let _result = transcript.append_scalar(b"z_two", &z_two);

        
        // Return InnerHaloProof 
        InnerHaloProof::new(l_vec, r_vec, r_comm, z_one, z_two)
    }
}
