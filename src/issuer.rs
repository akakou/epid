use bls12_381::{pairing, G1Projective, G2Projective, Gt, Scalar};
use ff::Field;
use group::{Curve, Group, GroupEncoding};
use rand::RngCore;

use super::utils::gen_rand_scalar;

struct GPK {
    pub g1: G1Projective,
    pub g2: G2Projective,
    pub g3: Gt,
    pub h1: G1Projective,
    pub h2: G1Projective,
    pub w: G2Projective,
}

struct ISK {
    pub gamma: Scalar,
}

struct Issuer {
    pub gpk: GPK,
    pub isk: ISK,
}

impl Issuer {
    fn random(rng: &mut impl RngCore) -> Self {
        let g1 = G1Projective::generator();
        let g2 = G2Projective::generator();
        let g3 = Gt::generator();

        let h1 = G1Projective::generator() * gen_rand_scalar(rng);
        let h2 = G1Projective::generator() * gen_rand_scalar(rng);

        let gamma = gen_rand_scalar(rng);
        let w = g2 * gamma;

        Self::new(g1, g2, g3, h1, h2, gamma, w)
    }

    fn new(
        g1: G1Projective,
        g2: G2Projective,
        g3: Gt,
        h1: G1Projective,
        h2: G1Projective,
        gamma: Scalar,
        w: G2Projective,
    ) -> Self {
        let gpk = GPK {
            g1,
            g2,
            g3,
            h1,
            h2,
            w,
        };

        let isk = ISK { gamma };

        Self { gpk, isk }
    }
}


#[test]
fn test_random() {
    use rand::thread_rng;
    let mut rng = thread_rng();
    Issuer::random(&mut rng);
}