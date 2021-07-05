use crate::zpk::ZPKSignature;
use bls12_381::{pairing, G1Projective, G2Projective, Gt, Scalar};
use core::ops::Add;
use core::ops::Mul;
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

pub struct PlatformAttestation {
    pub large_b: Gt,
    pub large_k: Gt,
    pub large_t: G1Projective,
    pub s_x: Scalar,
    pub s_f: Scalar,
    pub s_a: Scalar,
    pub s_b: Scalar,
    pub c: Scalar,
}

pub struct UnRevokedAttestation<
    C: GroupEncoding + Copy + Mul<Scalar, Output = C> + Add<C, Output = C> + Eq,
> {
    pub proof1: ZPKSignature<C>,
    pub proof2: ZPKSignature<C>,
}

pub struct Signature {
    pub platform_attestation: PlatformAttestation,
    pub unrevoked_attestations: Vec<UnRevokedAttestation<Gt>>,
}

pub struct Revocation {
    pub large_b: Gt,
    pub large_k: Gt,
}
