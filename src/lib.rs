use curve25519_dalek::scalar::Scalar as Scalar25519;
use sha2::{Digest, Sha512};
use bls12_381::G1Affine;
use bls12_381::Scalar as Scalar381;
use std::convert::TryInto;

use rand::Rng;
use rand::thread_rng;

const LAM: u8 = 128;

#[inline]
pub fn hash_tilde_curve25519(m: &[u8], n: usize, variant: bool) -> Vec<Scalar25519> {
    let mut hash = Sha512::default();
    hash.update([variant as u8]);
    hash.update(m);

    let mut result = Vec::with_capacity(n);
    for i in 0..n {
        let mut current = hash.clone();
        current.update([i as u8]);
        result.push(Scalar25519::from_hash(current));
    }
    result
}

#[inline]
pub fn sample_curve25519_lambda(n: usize) -> Vec<Scalar25519> {
    let mut rng = thread_rng();
    (0..n).map(|_| Scalar25519::from(rng.gen_range(0, LAM))).collect()
}

#[inline]
pub fn aggregate_curve25519(a: &[Scalar25519], b: &[Scalar25519]) -> Scalar25519 {
    let n = a.len();
    assert_eq!(n, b.len());
    (0..n).fold(Scalar25519::zero(), |sum, i| sum + a[i] * b[i])
}

#[inline]
pub fn curve25519_scalar_list_to_bytes(a: &[Scalar25519]) -> Vec<u8> {
    bincode::serialize(&a).unwrap()
}

#[inline]
pub fn hash_scalar_bls12_381(msg: &[u8]) -> Scalar381 {
    let mut msg_hash = Sha512::default();
    msg_hash.update(&msg);
    Scalar381::from_bytes_wide(&msg_hash.finalize().as_slice().try_into().unwrap())
}

#[inline]
pub fn hash_g1_bls12_381(msg: &[u8]) -> G1Affine {
    use bls12_381::G1Projective;
    use bls12_381::hash_to_curve::{HashToCurve, ExpandMsgXmd};

    let g = <G1Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::encode_to_curve(
        msg, "test_domain".as_bytes(),
    );
    G1Affine::from(g)
}

#[inline]
pub fn hash_tilde_bls12_381(m: &[u8], n: usize, variant: bool) -> Vec<Scalar381> {
    let mut hash = Sha512::default();
    hash.update([variant as u8]);
    hash.update(m);

    let mut result = Vec::with_capacity(n);
    for i in 0..n {
        let mut current = hash.clone();
        current.update([i as u8]);
        let current: [u8; 64] = current.finalize().as_slice().try_into().unwrap();
        result.push(Scalar381::from_bytes_wide(&current));
    }
    result
}

#[inline]
pub fn sample_bls12_381_lambda(n: usize) -> Vec<Scalar381> {
    let mut rng = thread_rng();
    (0..n).map(|_| Scalar381::from(rng.gen_range(0, LAM) as u64)).collect()
}

#[inline]
pub fn aggregate_bls12_381(a: &[Scalar381], b: &[Scalar381]) -> Scalar381 {
    let n = a.len();
    assert_eq!(n, b.len());
    (0..n).fold(Scalar381::zero(), |sum, i| sum + a[i] * b[i])
}

#[inline]
pub fn bls12_381_scalar_list_to_bytes(a: &[Scalar381]) -> Vec<u8> {
    let a_repr = format!{"{:?}", a};
    Vec::from(a_repr.as_bytes())
}


pub mod bls;
pub mod bb3;
pub mod ecdsa;
pub mod schnorr;
pub mod okamoto_aim;
pub mod okamoto_cml;