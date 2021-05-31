use bls12_381::Scalar;
use ff::Field;
use rand::RngCore;

pub fn gen_rand_scalar(rng: &mut impl RngCore) -> Scalar {
    Scalar::random(rng)
}
