use crate::core::Revocation;
use crate::verifier::Verifier;
use crate::*;

#[test]
fn test_all() {
    use rand::thread_rng;
    let mut rng = thread_rng();
    let issuer = issuer::Issuer::random(&mut rng);

    let gpk = issuer.gpk;

    /* make revocation list */

    let mut rl_platform_join = join::PlatformJoinProcess::new(gpk);
    let rl_join_req = rl_platform_join.gen_request(&mut rng);
    let rl_issuer_join = join::IssuerJoinProcess::new(issuer, rl_join_req);
    let rl_join_resp = rl_issuer_join
        .gen_join_response(&mut rng)
        .expect("genjoin resp error");

    let rl_platform = rl_platform_join
        .gen_platform(&rl_join_resp)
        .expect("gen platform error");

    let msg = vec![1, 2, 3];
    let rl_signature = rl_platform.sign(&msg, &vec![], &mut rng);

    let rl = vec![Revocation {
        large_k: rl_signature.platform_attestation.large_k,
        large_b: rl_signature.platform_attestation.large_b,
    }];

    let mut platform_join = join::PlatformJoinProcess::new(gpk);
    let join_req = platform_join.gen_request(&mut rng);
    let issuer_join = join::IssuerJoinProcess::new(issuer, join_req);
    let join_resp = issuer_join
        .gen_join_response(&mut rng)
        .expect("genjoin resp error");
    let platform = platform_join
        .gen_platform(&join_resp)
        .expect("gen platform error");

    let signature = platform.sign(&msg, &rl, &mut rng);

    let verifier = Verifier::new(gpk);
    verifier.verify(&signature, &msg).unwrap();

    let signature = rl_platform.sign(&msg, &rl, &mut rng);
    match verifier.verify(&signature, &msg) {
        Ok(_) => assert!(false),
        Err(_) => assert!(true),
    }
}
