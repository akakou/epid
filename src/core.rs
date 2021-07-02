use bls12_381::{pairing, G1Projective, G2Projective, Gt, Scalar};
use ff::Field;
use group::{Curve, Group, GroupEncoding};
use rand::RngCore;

#[derive(Copy, Clone)]
pub struct GPK {
    pub g1: G1Projective,
    pub g2: G2Projective,
    pub g3: Gt,
    pub h1: G1Projective,
    pub h2: G1Projective,
    pub w: G2Projective,
}

#[derive(Copy, Clone)]
pub struct ISK {
    pub gamma: Scalar,
}
