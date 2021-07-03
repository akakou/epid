use crate::platform::SK;
use bls12_381::{pairing, G1Projective, G2Projective, Scalar};
use ff::PrimeField;
use group::{Curve, GroupEncoding};

use rand::RngCore;

use crate::core::GPK;
use crate::utils::gen_rand_scalar;
use crate::{
    issuer::{self, Issuer},
    platform::Platform,
    utils::calc_sha256_scalar,
};

pub struct JoinRequest {
    pub large_t: G1Projective,
    pub large_y1: G1Projective,
    pub large_y2: G1Projective,
    pub y1: Scalar,
    pub y2: Scalar,
}

pub struct JoinResponse {
    pub large_a: G1Projective,
    pub x: Scalar,
    pub y_dash_dash: Scalar,
}

pub struct PlatformJoinProcess {
    gpk: GPK,
    f: Option<Scalar>,
    t: Option<G1Projective>,
    y_dash: Option<Scalar>,
    y_dash_dash: Option<Scalar>,
    y: Option<Scalar>,
}

impl PlatformJoinProcess {
    pub fn new(gpk: GPK) -> Self {
        Self {
            gpk,
            f: None,
            t: None,
            y_dash: None,
            y_dash_dash: None,
            y: None,
        }
    }

    pub fn gen_request(&mut self, rng: &mut impl RngCore) -> JoinRequest {
        let f = gen_rand_scalar(rng);
        let y_dash = gen_rand_scalar(rng);
        let large_t = self.gpk.h1 * f + self.gpk.h2 * y_dash;

        // PK {(f,y') : (h1^f) * (h2^y') = T}
        let r1 = gen_rand_scalar(rng);
        let r2 = gen_rand_scalar(rng);

        let large_y1 = self.gpk.h1 * r1;
        let large_y2 = self.gpk.h2 * r2;

        // b = hash(large_y1, large_y2, T)
        let mut vec: Vec<u8> = vec![];

        vec.append(&mut large_y1.to_bytes().as_mut().to_vec());
        vec.append(&mut large_y2.to_bytes().as_mut().to_vec());
        vec.append(&mut large_t.to_bytes().as_mut().to_vec());
        let b = calc_sha256_scalar(&vec);
        let y1 = r1 + b * f;
        let y2 = r2 + b * y_dash;

        self.f = Some(f);
        self.y_dash = Some(y_dash);

        JoinRequest {
            large_t,
            large_y1,
            large_y2,
            y1,
            y2,
        }
    }

    pub fn gen_platform(&self, resp: &JoinResponse) -> Result<Platform, ()> {
        let f = self.f.expect("gen_request have not done (f is None)");
        let y_dash = self
            .y_dash
            .expect("gen_request have not done (y_dash is None)");
        let y = y_dash + resp.y_dash_dash;

        self.check_resp(resp, y, f)?;

        let sk = SK {
            large_a: resp.large_a,
            x: resp.x,
            y,
            f,
        };

        Ok(Platform::new(self.gpk, sk))
    }

    fn check_resp(&self, resp: &JoinResponse, y: Scalar, f: Scalar) -> Result<(), ()> {
        let left1 = resp.large_a;
        let left2 = self.gpk.w + G2Projective::generator() * resp.x;

        let right1 = G1Projective::generator() + self.gpk.h1 * f + self.gpk.h2 * y;
        let right2 = G2Projective::generator();

        if pairing(&left1.to_affine(), &left2.to_affine())
            == pairing(&right1.to_affine(), &right2.to_affine())
        {
            Ok(())
        } else {
            Err(())
        }
    }
}

pub struct IssuerJoinProcess {
    issuer: Issuer,
    req: JoinRequest,
}

impl IssuerJoinProcess {
    pub fn new(issuer: Issuer, req: JoinRequest) -> Self {
        Self { issuer, req }
    }

    fn check_join_request(&self) -> Result<(), ()> {
        // b = hash(large_y1, large_y2, T)
        let mut vec: Vec<u8> = vec![];
        vec.append(&mut self.req.large_y1.to_bytes().as_mut().to_vec());
        vec.append(&mut self.req.large_y2.to_bytes().as_mut().to_vec());
        vec.append(&mut self.req.large_t.to_bytes().as_mut().to_vec());
        let b = calc_sha256_scalar(&vec);

        let left = (self.issuer.gpk.h1 * self.req.y1) + (self.issuer.gpk.h2 * self.req.y2);
        let right = self.req.large_y1 + self.req.large_y2 + self.req.large_t * b;
        if left == right {
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn gen_join_response(&self, rng: &mut impl RngCore) -> Result<JoinResponse, ()> {
        self.check_join_request()?;

        let x = gen_rand_scalar(rng);
        let y_dash_dash = gen_rand_scalar(rng);

        let base = G1Projective::generator() + self.req.large_t + self.issuer.gpk.h2 * y_dash_dash;
        let exp = (x + self.issuer.isk.gamma).invert().unwrap();

        let large_a = base * exp;

        Ok(JoinResponse {
            large_a,
            x,
            y_dash_dash,
        })
    }
}
