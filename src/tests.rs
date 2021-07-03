use crate::*;


#[test]
fn test_all() {
    use rand::thread_rng;
    let mut rng = thread_rng();
    let issuer = issuer::Issuer::random(&mut rng);

    let gpk = issuer.gpk;

    let mut platform_join = join::PlatformJoinProcess::new(gpk);
    let join_req = platform_join.gen_request(&mut rng);

    let issuer_join = join::IssuerJoinProcess::new(issuer, join_req);
    let join_resp = issuer_join.gen_join_response(&mut rng).expect("genjoin resp error");

    platform_join.gen_platform(&join_resp).expect("gen platform error");
}

