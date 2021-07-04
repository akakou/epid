use crate::platform::SK;
use crate::utils::pj_pairing;
use crate::zpk::zpk_sign;
use crate::zpk::zpk_verify;
use crate::zpk::ZPKSignature;
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
    pub signature: ZPKSignature,
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

    pub fn gen_request(&mut self, mut rng: &mut impl RngCore) -> JoinRequest {
        let GPK {
            h1,
            h2,
            g1: _,
            g2: _,
            g3: _,
            w: _,
        } = self.gpk;

        let f = gen_rand_scalar(rng);
        let y_dash = gen_rand_scalar(rng);
        let large_t = h1 * f + h2 * y_dash;

        // PK {(f,y') : (h1^f) * (h2^y') = T}
        let signature = zpk_sign(&f, &y_dash, &large_t, &self.gpk, &mut rng);

        self.f = Some(f);
        self.y_dash = Some(y_dash);

        JoinRequest { signature }
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
        let GPK {
            h1,
            h2,
            g1,
            g2,
            g3: _,
            w,
        } = self.gpk;
        let left1 = resp.large_a;
        let left2 = w + g2 * resp.x;

        let right1 = g1 + h1 * f + h2 * y;
        let right2 = g2;

        if pj_pairing(&left1, &left2) == pj_pairing(&right1, &right2) {
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

    pub fn gen_join_response(&self, mut rng: &mut impl RngCore) -> Result<JoinResponse, ()> {
        let gpk = self.issuer.gpk;

        let GPK {
            h1: _,
            h2,
            g1,
            g2: _,
            g3: _,
            w: _,
        } = gpk;

        zpk_verify(&self.req.signature, &gpk, &mut rng)?;

        let x = gen_rand_scalar(rng);
        let y_dash_dash = gen_rand_scalar(rng);

        let base = g1 + self.req.signature.large_t + h2 * y_dash_dash;
        let exp = (x + self.issuer.isk.gamma).invert().unwrap();

        let large_a = base * exp;

        Ok(JoinResponse {
            large_a,
            x,
            y_dash_dash,
        })
    }
}
