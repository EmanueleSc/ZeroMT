use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};

use crate::Utils;

pub struct PolyVector<'a> {
    left: &'a Vec<ScalarField>,
    right: &'a Vec<ScalarField>,
}

impl<'a> PolyVector<'a> {
    pub fn new(left: &'a Vec<ScalarField>, right: &'a Vec<ScalarField>) -> Self {
        PolyVector { left, right }
    }

    pub fn get_left(&self) -> &Vec<ScalarField> {
        self.left
    }

    pub fn get_right(&self) -> &Vec<ScalarField> {
        self.right
    }

    pub fn evaluate(&self, x: &ScalarField) -> Vec<ScalarField> {
        let right_x: Vec<ScalarField> = self.right.iter().map(|r: &ScalarField| *r * *x).collect();

        Utils::sum_scalar_scalar(self.left, &right_x).unwrap()
    }
}
