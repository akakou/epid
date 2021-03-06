use crate::core::PlatformAttestation;
use crate::core::Revocation;
use crate::core::Signature;
use crate::core::UnRevokedAttestation;
use crate::core::GPK;
use crate::utils::calc_sha256_scalar;
use crate::utils::pj_pairing;
use crate::zpk::zpk_verify;
use bls12_381::Gt;

use bls12_381::pairing;
use group::{Curve, GroupEncoding};

pub struct Verifier {
    pub gpk: GPK,
}

impl Verifier {
    pub fn new(gpk: GPK) -> Self {
        Self { gpk }
    }

    pub fn verify(&self, signature: &Signature, msg: &[u8], rl: &[Revocation]) -> Result<(), u8> {
        let GPK {
            h1,
            h2,
            w,
            g1,
            g2,
            g3: _,
        } = self.gpk;

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

        let large_r1 = large_b * s_f + large_k * (-c);

        let large_r2_1 = pj_pairing(&large_t, &g2) * (-s_x);

        let large_r2_2 = pj_pairing(&h1, &g2) * s_f;
        let large_r2_3 = pj_pairing(&h2, &g2) * s_b;
        let large_r2_4 = pj_pairing(&h2, &w) * s_a;

        let large_r2_5_1 = pj_pairing(&g1, &g2);
        let large_r2_5_2 = pj_pairing(&large_t, &w);

        let large_r2_5 = (large_r2_5_1 - large_r2_5_2) * c;
        let large_r2 = large_r2_1 + large_r2_2 + large_r2_3 + large_r2_4 + large_r2_5;

        let mut vec = vec![];
        vec.append(&mut large_b.to_bytes().as_ref().to_vec());
        vec.append(&mut large_k.to_bytes().as_ref().to_vec());
        vec.append(&mut large_t.to_bytes().as_ref().to_vec());
        vec.append(&mut large_r1.to_bytes().as_ref().to_vec());
        vec.append(&mut large_r2.to_bytes().as_ref().to_vec());
        vec.append(&mut msg.to_vec());

        let c_dash = calc_sha256_scalar(&vec);

        for (un_attest, r) in signature.unrevoked_attestations.iter().zip(rl.iter()) {
            let UnRevokedAttestation { mut proof1, proof2 } = &un_attest;
            proof1.large_a1 = r.large_b;
            proof1.large_a2 = -r.large_k;

            match zpk_verify(&proof1) {
                Ok(_) => {}
                Err(_) => return Err(1),
            };

            match zpk_verify(&proof2) {
                Ok(_) => {}
                Err(_) => return Err(2),
            };

            let one = Gt::identity();

            if proof1.large_beta == one {
                return Err(3);
            }
        }

        if c == c_dash {
            Ok(())
        } else {
            Err(0)
        }
    }
}
