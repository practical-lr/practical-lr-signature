use curve25519_dalek::scalar::Scalar as Scalar25519;
use bls12_381::Scalar as Scalar381;
use criterion::Criterion;
use criterion::{criterion_group, criterion_main};

use practical_lr::{bls, bb3, ecdsa, schnorr, okamoto};

fn bench_bls12_381(c: &mut Criterion) {
    let params: [usize; 4] = [1, 200, 400, 1998];
    let msg = "Hello, world!";

    let max_param = params[params.len() - 1];
    let group_name = format!("Tools(BLS12-381, n={})", max_param);
    let mut group = c.benchmark_group(&group_name);
    let a_list: Vec<Scalar381> = practical_lr::sample_bls12_381_lambda(max_param);
    let b_list: Vec<Scalar381> = (0..max_param).map(|i| practical_lr::hash_scalar_bls12_381(&[i as u8])).collect();
    group.bench_function("hash_tilde_bls12_381", |b| b.iter(|| practical_lr::hash_tilde_bls12_381(&practical_lr::bls12_381_scalar_list_to_bytes(&b_list), max_param, false)));
    group.bench_function("sample_bls12_381_lambda", |b| b.iter(|| practical_lr::sample_bls12_381_lambda(max_param)));
    group.bench_function("aggregate_bls12_381", |b| b.iter(|| practical_lr::aggregate_bls12_381(&a_list, &b_list)));
    group.bench_function("bls12_381_scalar_list_to_bytes", |b| b.iter(|| practical_lr::bls12_381_scalar_list_to_bytes(&b_list)));
    group.finish();

    for par in params {
        let group_name = format!("BLS(n={})", par);
        let mut group = c.benchmark_group(&group_name);

        let (sk, pk) = bls::keygen(par);
        let signature = bls::sign(&sk, &msg.as_bytes());
        // group.bench_function("KeyGen", |b| b.iter(|| ecdsa::keygen(par)));
        group.bench_function("Sign", |b| b.iter(|| bls::sign(&sk, &msg.as_bytes())));
        group.bench_function("Verify", |b| b.iter(|| bls::verify(&pk, &msg.as_bytes(), &signature)));

        group.finish();
    }

    for par in params {
        let group_name = format!("BB3(n={})", par);
        let mut group = c.benchmark_group(&group_name);

        let (sk, pk) = bb3::keygen(par);
        let signature = bb3::sign(&sk, &msg.as_bytes());
        // group.bench_function("KeyGen", |b| b.iter(|| ecdsa::keygen(par)));
        group.bench_function("Sign", |b| b.iter(|| bb3::sign(&sk, &msg.as_bytes())));
        group.bench_function("Verify", |b| b.iter(|| bb3::verify(&pk, &msg.as_bytes(), &signature)));

        group.finish();
    }

}

fn bench_curve25519(c: &mut Criterion) {
    let params: [usize; 4] = [1, 146, 291, 1455];
    let msg = "Hello, world!";

    let max_param = params[params.len() - 1];
    let group_name = format!("Tools(Curve25519, n={})", max_param);
    let mut group = c.benchmark_group(&group_name);
    let mut rng = rand::rngs::ThreadRng::default();
    let a_list: Vec<Scalar25519> = practical_lr::sample_curve25519_lambda(max_param);
    let b_list: Vec<Scalar25519> = (0..max_param).map(|_| Scalar25519::random(&mut rng)).collect();
    group.bench_function("hash_tilde_curve25519", |b| b.iter(|| practical_lr::hash_tilde_curve25519(&practical_lr::curve25519_scalar_list_to_bytes(&b_list), max_param, false)));
    group.bench_function("sample_curve25519_lambda", |b| b.iter(|| practical_lr::sample_curve25519_lambda(max_param)));
    group.bench_function("aggregate_curve25519", |b| b.iter(|| practical_lr::aggregate_curve25519(&a_list, &b_list)));
    group.bench_function("curve25519_scalar_list_to_bytes", |b| b.iter(|| practical_lr::curve25519_scalar_list_to_bytes(&b_list)));
    group.finish();

    for par in params {
        let group_name = format!("ECDSA(n={})", par);
        let mut group = c.benchmark_group(&group_name);

        let (sk, pk) = ecdsa::keygen(par);
        let signature = ecdsa::sign(&sk, &msg.as_bytes());
        // group.bench_function("KeyGen", |b| b.iter(|| ecdsa::keygen(par)));
        group.bench_function("Sign", |b| b.iter(|| ecdsa::sign(&sk, &msg.as_bytes())));
        group.bench_function("Verify", |b| b.iter(|| ecdsa::verify(&pk, &msg.as_bytes(), &signature)));

        group.finish();
    }

    for par in params {
        let group_name = format!("Schnorr(n={})", par);
        let mut group = c.benchmark_group(&group_name);

        let (sk, pk) = okamoto::keygen(par);
        let signature = okamoto::sign(&pk, &sk, &msg.as_bytes());
        group.bench_function("Sign", |b| b.iter(|| okamoto::sign(&pk, &sk, &msg.as_bytes())));
        group.bench_function("Verify", |b| b.iter(|| okamoto::verify(&pk, &msg.as_bytes(), &signature)));

        group.finish();
    }

    for par in params {
        let group_name = format!("Okamoto(n={})", par);
        let mut group = c.benchmark_group(&group_name);

        let (sk, pk) = schnorr::keygen(par);
        let signature = schnorr::sign(&sk, &msg.as_bytes());
        group.bench_function("Sign", |b| b.iter(|| schnorr::sign(&sk, &msg.as_bytes())));
        group.bench_function("Verify", |b| b.iter(|| schnorr::verify(&pk, &msg.as_bytes(), &signature)));

        group.finish();
    }
}

criterion_group!(benches, bench_curve25519, bench_bls12_381);
criterion_main!(benches);