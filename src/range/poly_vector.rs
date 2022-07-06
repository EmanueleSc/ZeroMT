use ark_bn254::Fr as ScalarField;

use crate::Utils;

pub struct PolyVector {
    left: Vec<ScalarField>,
    right: Vec<ScalarField>,
}

impl PolyVector {
    pub fn new(left: Vec<ScalarField>, right: Vec<ScalarField>) -> Self {
        PolyVector { left, right }
    }

    pub fn get_left(&self) -> &Vec<ScalarField> {
        &self.left
    }

    pub fn get_right(&self) -> &Vec<ScalarField> {
        &self.right
    }

    pub fn evaluate(&self, x: &ScalarField) -> Vec<ScalarField> {
        let right_x: Vec<ScalarField> = self.right.iter().map(|r: &ScalarField| *r * *x).collect();

        Utils::sum_scalar_scalar(&self.left, &right_x).unwrap()
    }
}
