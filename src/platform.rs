use crate::core::PlatformAttestation;
use crate::core::Revocation;
use crate::core::Signature;
use crate::core::UnRevokedAttestation;
use crate::utils::calc_sha256_scalar;
use crate::utils::gen_rand_scalar;
use crate::utils::pj_pairing;
use crate::zpk::zpk_sign;
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

    pub fn sign(&self, msg: &[u8], rl: &[Revocation], rng: &mut impl RngCore) -> Signature {
        let GPK {
            h1,
            h2,
            w,
            g1: _,
            g2,
            g3,
        } = self.gpk;

        let SK { f, x, y, large_a } = self.sk;

        let large_b = g3 * gen_rand_scalar(rng);
        let large_k = large_b * f;

        let a = gen_rand_scalar(rng);
        let b = y + a * x;
        let large_t = large_a + h2 * a;

        let r_x = gen_rand_scalar(rng);
        let r_f = gen_rand_scalar(rng);
        let r_a = gen_rand_scalar(rng);
        let r_b = gen_rand_scalar(rng);

        let large_r1 = large_b * r_f;
        let large_r2_1 = pj_pairing(&large_t, &g2) * (-r_x);
        let large_r2_2 = pj_pairing(&h1, &g2) * r_f;
        let large_r2_3 = pj_pairing(&h2, &g2) * r_b;
        let large_r2_4 = pj_pairing(&h2, &w) * r_a;
        let large_r2 = large_r2_1 + large_r2_2 + large_r2_3 + large_r2_4;

        // c = Hash(gpk, B, K, T, R1, R2, m).
        let mut vec: Vec<u8> = vec![];
        vec.append(&mut large_b.to_bytes().as_ref().to_vec());
        vec.append(&mut large_k.to_bytes().as_ref().to_vec());
        vec.append(&mut large_t.to_bytes().as_ref().to_vec());
        vec.append(&mut large_r1.to_bytes().as_ref().to_vec());
        vec.append(&mut large_r2.to_bytes().as_ref().to_vec());
        vec.append(&mut msg.to_vec());

        let c = calc_sha256_scalar(&vec);

        let s_x = r_x + c * x;
        let s_f = r_f + c * f;
        let s_a = r_a + c * a;
        let s_b = r_b + c * b;

        let mut unrevoked_attestations = vec![];

        for r in rl {
            // log_{B} K != log_{B1} K1
            // let rnd = gen_rand_scalar(rng);
            let zpk_b = gen_rand_scalar(rng);
            let zpk_a = zpk_b * f;

            let zpk_large_c = (r.large_b * f - r.large_k) * zpk_b;

            let proof1 = zpk_sign(&zpk_a, &zpk_b, &r.large_b, &(-r.large_k), &zpk_large_c, rng);

            let one = Gt::identity();
            let proof2 = zpk_sign(&zpk_a, &zpk_b, &large_b, &(-large_k), &one, rng);

            unrevoked_attestations.push(UnRevokedAttestation { proof1, proof2 });
        }

        let platform_attestation = PlatformAttestation {
            large_b,
            large_k,
            large_t,
            s_x,
            s_f,
            s_a,
            s_b,
            c,
        };

        Signature {
            platform_attestation,
            unrevoked_attestations,
        }
    }
}
