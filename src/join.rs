use bls12_381::{G1Projective, Scalar};
use group::GroupEncoding;

use rand::RngCore;

use crate::{platform::Platform, utils::calc_sha256_scalar};
use crate::utils::gen_rand_scalar;

pub struct JoinGenRequest {
    pub large_t: G1Projective,
    pub large_y1: G1Projective,
    pub large_y2: G1Projective,
    pub b: Scalar,
    pub y1: Scalar,
    pub y2: Scalar
}

pub struct IssuerJoinProcess {}

pub struct PlatformJoinProcess {
    platform: Platform,
    f: Option<Scalar>,
    t: Option<G1Projective>,
    y_dash: Option<Scalar>,
    y_dash_dash: Option<Scalar>,
    y: Option<Scalar>,
}

impl PlatformJoinProcess {
    pub fn new(platform: Platform) -> Self {
        Self {
            platform: platform,
            f: None,
            t: None,
            y_dash: None,
            y_dash_dash: None,
            y: None,
        }
    }

    pub fn gen_request(&self, rng: &mut impl RngCore) -> JoinGenRequest {
        let f = gen_rand_scalar(rng);
        let y_dash = gen_rand_scalar(rng);
        let large_t = self.platform.gpk.h1 * f + self.platform.gpk.h2 * y_dash;

        // PK {(f,y') : (h1^f) * (h2^y') = T}
        let r1 = gen_rand_scalar(rng);
        let r2 = gen_rand_scalar(rng);

        let large_y1 = self.platform.gpk.h1 * r1;
        let large_y2 = self.platform.gpk.h2 * r1;

        // b = hash(large_y1, large_y2, T)
        let mut vec: Vec<u8> = vec![];
        vec.append(&mut large_y1.to_bytes().as_mut().to_vec());
        vec.append(&mut large_y2.to_bytes().as_mut().to_vec());
        vec.append(&mut large_t.to_bytes().as_mut().to_vec());
        let b = calc_sha256_scalar(&vec);
        
        let y1 = r1 + b * f;
        let y2 = r2 + b * y_dash;

        JoinGenRequest {
            large_t,
            large_y1,
            large_y2,
            b,
            y1,
            y2
        }
    }
}
