use bls12_381::{G1Projective, Scalar};

use super::core::{GPK, ISK};

#[derive(Copy, Clone)]
pub struct SK {
    pub large_a : G1Projective,
    pub x: Scalar,
    pub y: Scalar,
    pub f: Scalar
}

pub struct Platform {
    pub gpk: GPK,
    pub sk: SK
}

impl Platform {
    pub fn new(gpk: GPK, sk: SK) -> Self {
        Self {gpk, sk}
    }
}
