use epid::core::Revocation;
use epid::issuer::Issuer;
use epid::join::IssuerJoinProcess;
use epid::join::PlatformJoinProcess;
use epid::verifier::Verifier;
use std::time::Instant;

fn main() {
    let rl_size = 1000;

    use rand::thread_rng;
    let mut rng = thread_rng();
    let issuer = Issuer::random(&mut rng);

    let gpk = issuer.gpk;

    let mut rl = vec![];

    let msg = vec![1, 2, 3, 4, 5, 6];

    for _ in 0..rl_size {
        let mut rl_platform_join = PlatformJoinProcess::new(gpk);
        let rl_join_req = rl_platform_join.gen_request(&mut rng);
        let rl_issuer_join = IssuerJoinProcess::new(issuer, rl_join_req);
        let rl_join_resp = rl_issuer_join
            .gen_join_response(&mut rng)
            .expect("genjoin resp error");

        let rl_platform = rl_platform_join
            .gen_platform(&rl_join_resp)
            .expect("gen platform error");

        let rl_signature = rl_platform.sign(&msg, &vec![], &mut rng);

        rl.push(Revocation {
            large_k: rl_signature.platform_attestation.large_k,
            large_b: rl_signature.platform_attestation.large_b,
        });
    }

    let mut platform_join = PlatformJoinProcess::new(gpk);
    let join_req = platform_join.gen_request(&mut rng);
    let issuer_join = IssuerJoinProcess::new(issuer, join_req);
    let join_resp = issuer_join
        .gen_join_response(&mut rng)
        .expect("genjoin resp error");
    let platform = platform_join
        .gen_platform(&join_resp)
        .expect("gen platform error");

    let start = Instant::now();
    let signature = platform.sign(&msg, &rl, &mut rng);
    let end = start.elapsed();
    println!(
        "署名：{}.{:03}秒経過しました。",
        end.as_secs(),
        end.subsec_nanos() / 1_000_000
    );

    let verifier = Verifier::new(gpk);
    let start = Instant::now();
    verifier.verify(&signature, &msg, &rl).unwrap();
    let end = start.elapsed();

    println!(
        "検証：{}.{:03}秒経過しました。",
        end.as_secs(),
        end.subsec_nanos() / 1_000_000
    );
}
