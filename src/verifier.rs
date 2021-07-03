use crate::core::PlatformAttestation;
use crate::core::Signature;
use crate::core::GPK;
use crate::utils::calc_sha256_scalar;

use bls12_381::pairing;
use group::{Curve, GroupEncoding};

pub struct Verifier {
    pub gpk: GPK,
}

impl Verifier {
    pub fn new(gpk: GPK) -> Self {
        Self { gpk }
    }

    pub fn verify(&self, signature: &Signature, msg: &[u8]) -> Result<(), ()> {
        let PlatformAttestation {
            large_b,
            large_k,
            large_t,
            s_x,
            s_f,
            s_a,
            s_b,
            c,
        } = signature.platform_attestation;

        let GPK {
            g1,
            g2,
            g3: _,
            h1,
            h2,
            w,
        } = self.gpk;

        let large_r1 = large_b * s_f + large_k * (-c);

        let large_r2_1 = pairing(&large_t.to_affine(), &g2.to_affine()) * (-s_x);

        let large_r2_2 = pairing(&h1.to_affine(), &g2.to_affine()) * s_f;
        let large_r2_3 = pairing(&h2.to_affine(), &g2.to_affine()) * s_b;
        let large_r2_4 = pairing(&h2.to_affine(), &w.to_affine()) * s_a;

        let large_r2_5_1 = pairing(&g1.to_affine(), &g2.to_affine());
        let large_r2_5_2 = pairing(&large_t.to_affine(), &w.to_affine());

        let large_r2_5 = (large_r2_5_1 - large_r2_5_2) * c;
        let large_r2 = large_r2_1 + large_r2_2 + large_r2_3 + large_r2_4 + large_r2_5;

        println!("{:x?}", large_r2);

        let mut vec = vec![];
        vec.append(&mut large_b.to_bytes().as_ref().to_vec());
        vec.append(&mut large_k.to_bytes().as_ref().to_vec());
        vec.append(&mut large_t.to_bytes().as_ref().to_vec());
        vec.append(&mut large_r1.to_bytes().as_ref().to_vec());
        vec.append(&mut large_r2.to_bytes().as_ref().to_vec());
        vec.append(&mut msg.to_vec());

        let c_dash = calc_sha256_scalar(&vec);

        if c == c_dash {
            Ok(())
        } else {
            Err(())
        }
    }
}
