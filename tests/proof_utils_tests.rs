// local functions
pub fn add_two(a: i32) -> i32 {
    a + 2
}

pub fn panic_with_message(a: i32) -> i32 {
    if a < 0 {
        panic!("negative values, got '{}'", a);
    }
    a
}

#[cfg(test)]
mod proof_utils_tests {
    /* GUIDE:
    *  src/lib.rs is required to use external modules of a binary project 
    *  e.g. following the structure of src/lib.rs you can use the module 'crate::proof_utils::ProofUtils'
    *
    *  To run all tests run command: 'cargo test' 
    */

    use zeromt::ProofUtils;
    use super::*; // needed to load local functions etc.. of this test module

    #[test]
    fn generator_is_on_curve_test() {
        let mut rng = &mut ark_std::test_rng();
        let num_gens = 1;
        let gens = ProofUtils::get_generators(num_gens, &mut rng);
        
        // assert true
        assert!(gens[0].is_on_curve());
    }
    
    #[test]
    #[should_panic]
    // example of failing test
    fn failing_test() {
        panic!("Make this test fail");
    }

    #[test]
    // test with local function 'add_two'
    // we can call it because of 'use super::*'
    fn local_fn_test() {
        // assert equal
        assert_eq!(4, add_two(2));
        // assert not equal: 'assert_ne!()'
    }

    #[test]
    #[should_panic]
    // example of failing test with custom fail message
    fn contain_name_test() {
        let s1 = "hello pippo";
        let s2 = "pluto";
        assert!(
            s1.contains(s2),
            "The string was '{}' and not contain '{}'", s1, s2
        )
    }

    #[test]
    #[should_panic(expected = "negative values")]
    // example of failing test with custom fail message
    fn panic_message_test() {
        panic_with_message(-1); // pass because the message error "negative values" is what we expect
        // panic_with_message(0); // this fails
    }

    #[test]
    // tests can return a Result type
    fn return_result_test() -> Result<(), String> {
        if true {
            Ok(())
        } else {
            Err(String::from("This never occurs"))
        }
    }

}

