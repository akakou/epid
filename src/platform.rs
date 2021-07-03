use crate::core::PlatformAttestation;
use crate::core::Signature;
use crate::utils::calc_sha256_scalar;
use crate::utils::gen_rand_scalar;
use bls12_381::pairing;
use bls12_381::G2Projective;
use bls12_381::{G1Projective, Gt, Scalar};
use group::{Curve, Group, GroupEncoding};
use rand::RngCore;

use super::core::{GPK, ISK};

#[derive(Copy, Clone)]
pub struct SK {
    pub large_a: G1Projective,
    pub x: Scalar,
    pub y: Scalar,
    pub f: Scalar,
}

pub struct Platform {
    pub gpk: GPK,
    pub sk: SK,
}

impl Platform {
    pub fn new(gpk: GPK, sk: SK) -> Self {
        Self { gpk, sk }
    }

    pub fn sign(&self, msg: &[u8], rng: &mut impl RngCore) -> Signature {
        let hash = calc_sha256_scalar(msg);
        let large_b = Gt::generator() * gen_rand_scalar(rng);
        let large_k = large_b * self.sk.f;

        let a = gen_rand_scalar(rng);
        let b = self.sk.y + a * self.sk.x;
        let large_t = self.sk.large_a + self.gpk.h2 * a;

        let r_x = gen_rand_scalar(rng);
        let r_f = gen_rand_scalar(rng);
        let r_a = gen_rand_scalar(rng);
        let r_b = gen_rand_scalar(rng);

        let large_r_1 = large_b * r_f;
        let large_r_2_1 =
            pairing(&large_t.to_affine(), &G2Projective::generator().to_affine()) * (-r_x);

        let large_r_2_2 = pairing(
            &self.gpk.h1.to_affine(),
            &G2Projective::generator().to_affine(),
        ) * r_f;

        let large_r_2_3 = pairing(
            &self.gpk.h2.to_affine(),
            &G2Projective::generator().to_affine(),
        ) * r_b;

        let large_r_2_4 = pairing(&self.gpk.h2.to_affine(), &self.gpk.w.to_affine()) * r_a;

        let large_r_2 = large_r_2_1 + large_r_2_2 + large_r_2_3 + large_r_2_4;

        // c = Hash(gpk, B, K, T, R1, R2, m).
        let mut vec: Vec<u8> = vec![];
        // vec.append(&mut large_b..to_bytes());
        // to_bytes().as_mut().to_vec());
        vec.append(&mut large_b.to_bytes().as_ref().to_vec());
        vec.append(&mut large_k.to_bytes().as_ref().to_vec());
        vec.append(&mut large_t.to_bytes().as_ref().to_vec());
        vec.append(&mut large_r_1.to_bytes().as_ref().to_vec());
        vec.append(&mut large_r_2.to_bytes().as_ref().to_vec());
        vec.append(&mut msg.to_vec());

        let c = calc_sha256_scalar(&vec);

        let s_x = r_x + c * self.sk.x;
        let s_f = r_f + c * self.sk.f;
        let s_a = r_a + c * a;
        let s_b = r_b + c * b;

        let platform_attestation = PlatformAttestation {
            large_b,
            large_k,
            large_t,
            s_x,
            s_f,
            s_a,
            s_b,
        };

        Signature {
            platform_attestation,
        }
    }
}
