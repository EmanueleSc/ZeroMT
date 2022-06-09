use ark_bn254::{Fr as ScalarField};

pub struct PolyVector<'a> {
    coefficients: &'a Vec<Vec<ScalarField>>
}

impl<'a> PolyVector<'a> {
    pub fn new(
        coefficients: &'a Vec<Vec<ScalarField>>
    ) -> Self {
        PolyVector { 
            coefficients 
        }
    }

    pub fn get_coefficients(&self) -> &Vec<Vec<ScalarField>> {
        self.coefficients
    }

    /* pub fn get_t_0(&self) -> &ScalarField {
        &self.t_0
    }

    pub fn get_t_1(&self) -> &ScalarField {
        &self.t_1
    }
    pub fn get_t_2(&self) -> &ScalarField {
        &self.t_2
    }

    pub fn evaluate(&self, x: &ScalarField) -> ScalarField {
        self.t_0 + (*x * self.t_1) + (*x * *x * self.t_2)
    } */
}