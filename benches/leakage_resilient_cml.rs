use criterion::Criterion;
use criterion::{criterion_group, criterion_main};

use practical_lr::{bls, bb3_cml, ecdsa, schnorr, okamoto_cml};

fn bench_bls12_381(c: &mut Criterion) {
    let params: [usize; 3] = [400, 800, 3996];
    let msg = "Hello, world!";

    for par in params {
        let group_name = format!("CML_BLS(n={})", par);
        let mut group = c.benchmark_group(&group_name);

        let (sk, _) = bls::keygen(par);
        // let signature = bls::sign(&sk, &msg.as_bytes());
        // group.bench_function("KeyGen", |b| b.iter(|| ecdsa::keygen(par)));
        group.bench_function("Sign", |b| b.iter(|| bls::sign(&sk, &msg.as_bytes())));
        // group.bench_function("Verify", |b| b.iter(|| bls::verify(&pk, &msg.as_bytes(), &signature)));

        group.finish();
    }

    for par in params {
        let group_name = format!("CML_BB3(n={})", par);
        let mut group = c.benchmark_group(&group_name);

        let (sk, _) = bb3_cml::keygen(par);
        // let signature = bb3::sign(&sk, &msg.as_bytes());
        // group.bench_function("KeyGen", |b| b.iter(|| ecdsa::keygen(par)));
        group.bench_function("Sign", |b| b.iter(|| bb3_cml::sign(&sk, &msg.as_bytes())));
        // group.bench_function("Verify", |b| b.iter(|| bb3::verify(&pk, &msg.as_bytes(), &signature)));

        group.finish();
    }

}

fn bench_curve25519(c: &mut Criterion) {
    let params: [usize; 3] = [292, 582, 2910];
    let msg = "Hello, world!";

    for par in params {
        let group_name = format!("CML_ECDSA(n={})", par);
        let mut group = c.benchmark_group(&group_name);

        let (sk, _) = ecdsa::keygen(par);
        // let signature = ecdsa::sign(&sk, &msg.as_bytes());
        // group.bench_function("KeyGen", |b| b.iter(|| ecdsa::keygen(par)));
        group.bench_function("Sign", |b| b.iter(|| ecdsa::sign(&sk, &msg.as_bytes())));
        // group.bench_function("Verify", |b| b.iter(|| ecdsa::verify(&pk, &msg.as_bytes(), &signature)));

        group.finish();
    }

    for par in params {
        let group_name = format!("CML_Okamoto(n={})", par);
        let mut group = c.benchmark_group(&group_name);

        let (sk, pk) = okamoto_cml::keygen(par);
        // let signature = okamoto_cml::sign(&pk, &sk, &msg.as_bytes());
        group.bench_function("Sign", |b| b.iter(|| okamoto_cml::sign(&pk, &sk, &msg.as_bytes())));
        // group.bench_function("Verify", |b| b.iter(|| okamoto_cml::verify(&pk, &msg.as_bytes(), &signature)));

        group.finish();
    }

    for par in params {
        let group_name = format!("CML_Schnorr(n={})", par);
        let mut group = c.benchmark_group(&group_name);

        let (sk, pk) = schnorr::keygen(par);
        // let signature = schnorr::sign(&pk, &sk, &msg.as_bytes());
        group.bench_function("Sign", |b| b.iter(|| schnorr::sign(&pk, &sk, &msg.as_bytes())));
        // group.bench_function("Verify", |b| b.iter(|| schnorr::verify(&pk, &msg.as_bytes(), &signature)));

        group.finish();
    }
}

criterion_group!(benches, bench_curve25519, bench_bls12_381);
criterion_main!(benches);