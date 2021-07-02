use crate::*;


#[test]
fn test_all() {
    use rand::thread_rng;
    let mut rng = thread_rng();
    let issuer = issuer::Issuer::random(&mut rng);

    let gpk = issuer.gpk;

    let platform = platform::Platform::new(gpk);
    let platform_join = join::PlatformJoinProcess::new(platform);
    let gen_req = platform_join.gen_request(&mut rng);

    let issuer_join = join::IssuerJoinProcess::new(issuer);
    issuer_join.check_join_req(&gen_req).expect("issuer: join requst wrong");
}

