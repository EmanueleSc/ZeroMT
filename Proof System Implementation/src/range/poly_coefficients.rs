use ark_bn254::Fr as ScalarField;

use crate::Utils;

use super::poly_vector::PolyVector;

pub struct PolyCoefficients {
    t_1: ScalarField,
    t_2: ScalarField,
}

impl PolyCoefficients {
    pub fn new(l_poly_vector: &PolyVector, r_poly_vector: &PolyVector) -> Self {
        let t_0: ScalarField =
            Utils::inner_product_scalar_scalar(l_poly_vector.get_left(), r_poly_vector.get_left())
                .unwrap();

        let t_2: ScalarField = Utils::inner_product_scalar_scalar(
            l_poly_vector.get_right(),
            r_poly_vector.get_right(),
        )
        .unwrap();

        let t_1: ScalarField = Utils::inner_product_scalar_scalar(
            &Utils::sum_scalar_scalar(l_poly_vector.get_left(), l_poly_vector.get_right()).unwrap(),
            &Utils::sum_scalar_scalar(r_poly_vector.get_left(), r_poly_vector.get_right()).unwrap(),
        )
        .unwrap()
            + -t_0
            + -t_2;

        PolyCoefficients { t_1, t_2 }
    }

    pub fn get_t_1(&self) -> &ScalarField {
        &self.t_1
    }
    pub fn get_t_2(&self) -> &ScalarField {
        &self.t_2
    }
}
