#[cfg(test)]
mod proof_utils_tests {
    use ark_ff::Zero;
    use zeromt::BulletshortProver;
    use zeromt::ProofUtils;
    use ark_bn254::{Fr as ScalarField};

    #[test]
    fn a_l_a_r_tests() {
        let b1: u8 = 1;
        let b2: u8 = 2;
        
        // ---> Test mock array = generated bits array for a_l
        let a_l_bits_mock = vec![
            1,0,0,0,0,0,0,0, // b1
            0,1,0,0,0,0,0,0  // b2
        ];
        let a_l_bits = BulletshortProver::concat_bytes_to_bits(&vec![b1, b2]);

        assert_eq!(a_l_bits_mock, a_l_bits);
        // <----------------------------------------------------

        // ---> Test <a_l_b1, 2^n> = b1 and <a_l_b2, 2^n> = b2
        let a_l = BulletshortProver::get_a_l(b1, b2);
        let a_l_b1 = &a_l[0..8].to_vec();
        let a_l_b2 = &a_l[8..].to_vec();
        let exp_twos = BulletshortProver::generate_scalar_exp_vector(
            8, 
            &ScalarField::from(2)
        );
        let ipss = BulletshortProver::inner_product_scalar_scalar(a_l_b1, &exp_twos).unwrap();
        let b1s = ScalarField::from(b1);
        let ipss2 = BulletshortProver::inner_product_scalar_scalar(a_l_b2, &exp_twos).unwrap();
        let b2s = ScalarField::from(b2);
        
        assert_eq!(a_l_b1.len(), 8);
        assert_eq!(a_l_b2.len(), 8);
        assert_eq!(exp_twos.len(), 8);
        assert_eq!(ipss, b1s);
        assert_eq!(ipss2, b2s);
        // <----------------------------------------------------

        // Test (a_l hadamard product a_r) = zeros vector
        let mut zeros = Vec::with_capacity(16);
        for _ in 0..16 { zeros.push(ScalarField::zero()); } 
        let a_r = BulletshortProver::get_a_r(&a_l);
        let a_l_hadamard_a_r = BulletshortProver::hadamard_product_scalar_scalar(
            &a_l, 
            &a_r
        ).unwrap();

        assert_eq!(zeros.len(), 16);
        assert_eq!(a_l.len(), 16);
        assert_eq!(a_r.len(), 16);
        assert_eq!(a_l_hadamard_a_r, zeros);
        // <----------------------------------------------------

        // Test (a_l - ones vector) - a_r = zeros vector
        let mut ones = Vec::with_capacity(16);
        for _ in 0..16 { ones.push(ScalarField::from(1)); }
        let a_l_diff = BulletshortProver::subtract_scalar_scalar(
            &a_l, 
            &ones
        ).unwrap();
        let diff = BulletshortProver::subtract_scalar_scalar(
            &a_l_diff,
            &a_r
        ).unwrap();

        assert_eq!(diff, zeros);
        // <----------------------------------------------------
    }

    #[test]
    fn s_l_s_r_tests() {
        let n: usize = 8;       // 2 bytes size = 8 bits values
        let m = 2 * n;   // 2 values, 16 bits in total
        let rng = &mut ark_std::test_rng();
        let s_l: Vec<ScalarField> = ProofUtils::get_n_random_scalars(m, rng);
        let s_r: Vec<ScalarField> = ProofUtils::get_n_random_scalars(m, rng);

        assert_eq!(s_l.len(), 16);
        assert_eq!(s_r.len(), 16);
        assert_ne!(s_l, s_r);
    }

}

