use bls12_381::{Scalar, G1Affine, G2Affine, pairing};
use group::Curve;

use super::{aggregate_bls12_381, sample_bls12_381_lambda, hash_tilde_bls12_381, bls12_381_scalar_list_to_bytes, hash_g1_bls12_381};

pub fn keygen(n: usize) -> (Vec<Scalar>, G2Affine) {
    let sk = sample_bls12_381_lambda(n);
    let a_list = hash_tilde_bls12_381(&bls12_381_scalar_list_to_bytes(&sk), n, false);
    let pk = G2Affine::generator() * aggregate_bls12_381(&a_list, &sk);
    (sk, pk.to_affine())
}

pub fn sign(sk: &[Scalar], msg: &[u8]) -> G1Affine {
    let n = sk.len();
    let msg_hash = hash_g1_bls12_381(&msg);
    let a_list = hash_tilde_bls12_381(&bls12_381_scalar_list_to_bytes(&sk), n, false);
    (msg_hash * aggregate_bls12_381(&a_list, &sk)).to_affine()
}

pub fn verify(pk: &G2Affine, msg: &[u8], signature: &G1Affine) -> bool {
    let msg_hash = hash_g1_bls12_381(&msg);
    pairing(signature, &G2Affine::generator()) == pairing(&msg_hash, pk)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_lr_bls() {
        let n = 100;
        let msg = "Hello, world!";
        let (sk, pk) = keygen(n);
        let signature = sign(&sk, &msg.as_bytes());
        assert!(verify(&pk, &msg.as_bytes(), &signature))
    }
}