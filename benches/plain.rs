use criterion::Criterion;
use criterion::{criterion_group, criterion_main};

use practical_lr::{bls, bb3, ecdsa, schnorr, okamoto_aim};

fn bench_plain_signature(c: &mut Criterion) {
    let msg = "Hello, world!";
    let par = 1usize;
    {
        let group_name = format!("BLS(n={})", par);
        let mut group = c.benchmark_group(&group_name);

        let (sk, pk) = bls::keygen(par);
        let signature = bls::sign(&sk, &msg.as_bytes());
        // group.bench_function("KeyGen", |b| b.iter(|| ecdsa::keygen(par)));
        group.bench_function("Sign", |b| b.iter(|| bls::sign(&sk, &msg.as_bytes())));
        group.bench_function("Verify", |b| b.iter(|| bls::verify(&pk, &msg.as_bytes(), &signature)));

        group.finish();
    }

    {
        let group_name = format!("BB3(n={})", par);
        let mut group = c.benchmark_group(&group_name);

        let (sk, pk) = bb3::keygen(par);
        let signature = bb3::sign(&sk, &msg.as_bytes());
        // group.bench_function("KeyGen", |b| b.iter(|| ecdsa::keygen(par)));
        group.bench_function("Sign", |b| b.iter(|| bb3::sign(&sk, &msg.as_bytes())));
        group.bench_function("Verify", |b| b.iter(|| bb3::verify(&pk, &msg.as_bytes(), &signature)));

        group.finish();
    }

    {
        let group_name = format!("ECDSA(n={})", par);
        let mut group = c.benchmark_group(&group_name);

        let (sk, pk) = ecdsa::keygen(par);
        let signature = ecdsa::sign(&sk, &msg.as_bytes());
        // group.bench_function("KeyGen", |b| b.iter(|| ecdsa::keygen(par)));
        group.bench_function("Sign", |b| b.iter(|| ecdsa::sign(&sk, &msg.as_bytes())));
        group.bench_function("Verify", |b| b.iter(|| ecdsa::verify(&pk, &msg.as_bytes(), &signature)));

        group.finish();
    }

    {
        let group_name = format!("Okamoto(n={})", par);
        let mut group = c.benchmark_group(&group_name);

        let (sk, pk) = okamoto_aim::keygen(par);
        let signature = okamoto_aim::sign(&pk, &sk, &msg.as_bytes());
        group.bench_function("Sign", |b| b.iter(|| okamoto_aim::sign(&pk, &sk, &msg.as_bytes())));
        group.bench_function("Verify", |b| b.iter(|| okamoto_aim::verify(&pk, &msg.as_bytes(), &signature)));

        group.finish();
    }

    {
        let group_name = format!("Schnorr(n={})", par);
        let mut group = c.benchmark_group(&group_name);

        let (sk, pk) = schnorr::keygen(par);
        let signature = schnorr::sign(&pk, &sk, &msg.as_bytes());
        group.bench_function("Sign", |b| b.iter(|| schnorr::sign(&pk, &sk, &msg.as_bytes())));
        group.bench_function("Verify", |b| b.iter(|| schnorr::verify(&pk, &msg.as_bytes(), &signature)));

        group.finish();
    }
}

criterion_group!(benches, bench_plain_signature);
criterion_main!(benches);