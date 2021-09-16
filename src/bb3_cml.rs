use bls12_381::{Scalar, G1Affine, G2Affine, pairing};
use group::Curve;
use rand::Rng;
use rand::rngs::ThreadRng;


use super::{aggregate_bls12_381, sample_bls12_381_lambda, hash_tilde_bls12_381, bls12_381_scalar_list_to_bytes, hash_scalar_bls12_381};

pub fn keygen(n: usize) -> ((Vec<Scalar>, Vec<Scalar>), (G2Affine, G2Affine)) {
    let sk1 = sample_bls12_381_lambda(n);
    let sk2 = sample_bls12_381_lambda(n);
    let a_list = hash_tilde_bls12_381(&bls12_381_scalar_list_to_bytes(&sk1), n, false);
    let b_list = hash_tilde_bls12_381(&bls12_381_scalar_list_to_bytes(&sk2), n, true);
    let u = G2Affine::generator() * aggregate_bls12_381(&a_list, &sk1);
    let v = G2Affine::generator() * aggregate_bls12_381(&b_list, &sk2);
    ((sk1, sk2), (u.to_affine(), v.to_affine()))
}

pub fn sign(sk: &(Vec<Scalar>, Vec<Scalar>), msg: &[u8]) -> (G1Affine, Scalar) {
    let (sk1, sk2) = sk;
    let mut rng = ThreadRng::default();
    let n = sk1.len();
    let msg_hash = hash_scalar_bls12_381(msg);
    let a_list = hash_tilde_bls12_381(&bls12_381_scalar_list_to_bytes(&sk1), n, false);
    let b_list = hash_tilde_bls12_381(&bls12_381_scalar_list_to_bytes(&sk2), n, true);
    let mut r = [0u8; 64];
    rng.fill(&mut r);
    let r = Scalar::from_bytes_wide(&r);
    let pow = msg_hash + aggregate_bls12_381(&a_list, &sk1) + r * aggregate_bls12_381(&b_list, &sk2);
    ((G1Affine::generator() * pow.invert().unwrap()).to_affine(), r)
}

pub fn verify(pk: &(G2Affine, G2Affine), msg: &[u8], signature: &(G1Affine, Scalar)) -> bool {
    let (u, v) = pk;
    let (s, r) = signature;
    let msg_hash = hash_scalar_bls12_381(&msg);
    pairing(s, &(u + (G2Affine::generator() * msg_hash) + (v * r)).to_affine()) == pairing(&G1Affine::generator(), &G2Affine::generator())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_lr_bb3_cml() {
        let n = 100;
        let msg = "Hello, world!";
        let (sk, pk) = keygen(n);
        let signature = sign(&sk, &msg.as_bytes());
        assert!(verify(&pk, &msg.as_bytes(), &signature))
    }
}