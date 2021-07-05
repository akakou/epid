use crate::core::GPK;
use crate::utils::calc_sha256_scalar;
use crate::utils::gen_rand_scalar;
use crate::utils::pj_pairing;
use bls12_381::G1Projective;
use bls12_381::G2Projective;
use bls12_381::Scalar;
use core::ops::Add;
use core::ops::Mul;
use group::GroupEncoding;
use rand::RngCore;

#[derive(Copy, Clone)]
pub struct ZPKSignature<C: GroupEncoding + Copy + Mul<Scalar, Output = C> + Add<Output = C> + Eq> {
    pub y1: Scalar,
    pub y2: Scalar,
    pub large_a1: C,
    pub large_a2: C,
    pub large_y1: C,
    pub large_y2: C,
    pub large_beta: C,
}

pub fn zpk_sign<C: GroupEncoding + Copy + Mul<Scalar, Output = C> + Add<Output = C> + Eq>(
    x1: &Scalar,
    x2: &Scalar,
    large_a1: &C,
    large_a2: &C,
    large_beta: &C,
    rng: &mut impl RngCore,
) -> ZPKSignature<C> {
    let r1 = gen_rand_scalar(rng);
    let r2 = gen_rand_scalar(rng);

    let large_y1 = *large_a1 * r1;
    let large_y2 = *large_a2 * r2;

    // b = hash(large_y1, large_y2, T)
    let mut vec: Vec<u8> = vec![];

    vec.append(&mut large_y1.to_bytes().as_mut().to_vec());
    vec.append(&mut large_y2.to_bytes().as_mut().to_vec());
    vec.append(&mut large_beta.to_bytes().as_mut().to_vec());
    let b = calc_sha256_scalar(&vec);
    let y1 = r1 + b * x1;
    let y2 = r2 + b * x2;

    ZPKSignature {
        large_y1,
        large_y2,
        large_beta: *large_beta,
        y1,
        y2,
        large_a1: *large_a1,
        large_a2: *large_a2,
    }
}

pub fn zpk_verify<C: GroupEncoding + Copy + Mul<Scalar, Output = C> + Add<C, Output = C> + Eq>(
    signature: &ZPKSignature<C>,
) -> Result<(), ()> {
    let ZPKSignature {
        large_y1,
        large_y2,
        large_beta,
        y1,
        y2,
        large_a1,
        large_a2,
    } = signature;

    // b = hash(large_y1, large_y2, T)
    let mut vec: Vec<u8> = vec![];
    vec.append(&mut large_y1.to_bytes().as_mut().to_vec());
    vec.append(&mut large_y2.to_bytes().as_mut().to_vec());
    vec.append(&mut large_beta.to_bytes().as_mut().to_vec());
    let b = calc_sha256_scalar(&vec);

    let left = *large_a1 * *y1 + *large_a2 * *y2;
    let right = *large_y1 + *large_y2 + *large_beta * b;
    if left == right {
        Ok(())
    } else {
        Err(())
    }
}
