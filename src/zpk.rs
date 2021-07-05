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

pub struct ZPKSignature<C: GroupEncoding + Copy + Mul<Scalar, Output = C> + Add<Output = C> + Eq> {
    pub y1: Scalar,
    pub y2: Scalar,
    pub h1: C,
    pub h2: C,
    pub large_y1: C,
    pub large_y2: C,
    pub large_t: C,
}

pub fn zpk_sign<C: GroupEncoding + Copy + Mul<Scalar, Output = C> + Add<Output = C> + Eq>(
    f: &Scalar,
    y_dash: &Scalar,
    h1: &C,
    h2: &C,
    large_t: &C,
    gpk: &GPK,
    rng: &mut impl RngCore,
) -> ZPKSignature<C> {
    let GPK {
        h1: _,
        h2: _,
        w,
        g1: _,
        g2,
        g3,
    } = gpk;

    let r1 = gen_rand_scalar(rng);
    let r2 = gen_rand_scalar(rng);

    let large_y1 = *h1 * r1;
    let large_y2 = *h2 * r2;

    // b = hash(large_y1, large_y2, T)
    let mut vec: Vec<u8> = vec![];

    vec.append(&mut large_y1.to_bytes().as_mut().to_vec());
    vec.append(&mut large_y2.to_bytes().as_mut().to_vec());
    vec.append(&mut large_t.to_bytes().as_mut().to_vec());
    let b = calc_sha256_scalar(&vec);
    let y1 = r1 + b * f;
    let y2 = r2 + b * y_dash;

    ZPKSignature {
        large_y1,
        large_y2,
        large_t: *large_t,
        y1,
        y2,
        h1: *h1,
        h2: *h2,
    }
}

pub fn zpk_verify<C: GroupEncoding + Copy + Mul<Scalar, Output = C> + Add<C, Output = C> + Eq>(
    signature: &ZPKSignature<C>,
) -> Result<(), ()> {
    let ZPKSignature {
        large_y1,
        large_y2,
        large_t,
        y1,
        y2,
        h1,
        h2,
    } = signature;

    // b = hash(large_y1, large_y2, T)
    let mut vec: Vec<u8> = vec![];
    vec.append(&mut large_y1.to_bytes().as_mut().to_vec());
    vec.append(&mut large_y2.to_bytes().as_mut().to_vec());
    vec.append(&mut large_t.to_bytes().as_mut().to_vec());
    let b = calc_sha256_scalar(&vec);

    let left = *h1 * *y1 + *h2 * *y2;
    let right = *large_y1 + *large_y2 + *large_t * b;
    if left == right {
        Ok(())
    } else {
        Err(())
    }
}
