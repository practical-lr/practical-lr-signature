use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use sha2::{Digest, Sha512};

use super::{aggregate_curve25519, sample_curve25519_lambda, hash_tilde_curve25519, curve25519_scalar_list_to_bytes};

pub fn keygen(n: usize) -> (Vec<Scalar>, RistrettoPoint) {
    let sk = sample_curve25519_lambda(n);
    let a_list = hash_tilde_curve25519(&curve25519_scalar_list_to_bytes(&sk), n, false);
    let pk = RISTRETTO_BASEPOINT_POINT * aggregate_curve25519(&a_list, &sk);
    (sk, pk)
}

pub fn sign(pk: &RistrettoPoint, sk: &[Scalar], msg: &[u8]) -> (Scalar, Scalar) {
    let n = sk.len();
    let msg_hash = Scalar::hash_from_bytes::<Sha512>(msg);
    let a_list = hash_tilde_curve25519(&curve25519_scalar_list_to_bytes(&sk), n, false);
    let r_list = sample_curve25519_lambda(n);
    let b_list = hash_tilde_curve25519(&curve25519_scalar_list_to_bytes(&r_list), n, true);
    let point = RISTRETTO_BASEPOINT_POINT * aggregate_curve25519(&b_list, &r_list);

    let mut c_hash = Sha512::default();
    c_hash.update(pk.compress().as_bytes());
    c_hash.update(msg_hash.as_bytes());
    c_hash.update(point.compress().as_bytes());
    let c = Scalar::from_hash::<Sha512>(c_hash);

    let z = aggregate_curve25519(&b_list, &r_list) + c * aggregate_curve25519(&a_list, &sk);
    (c, z)
}

pub fn verify(pk: &RistrettoPoint, msg: &[u8], signature: &(Scalar, Scalar)) -> bool {
    let (c, z) = signature;
    let msg_hash = Scalar::hash_from_bytes::<Sha512>(msg);

    let mut c_candidate_hash = Sha512::default();
    c_candidate_hash.update(pk.compress().as_bytes());
    c_candidate_hash.update(msg_hash.as_bytes());
    c_candidate_hash.update((RISTRETTO_BASEPOINT_POINT * z + pk * (-c)).compress().as_bytes());

    c == &Scalar::from_hash::<Sha512>(c_candidate_hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_lr_schnorr() {
        let n = 100;
        let msg = "Hello, world!";
        let (sk, pk) = keygen(n);
        let signature = sign(&pk, &sk, &msg.as_bytes());
        assert!(verify(&pk, &msg.as_bytes(), &signature))
    }
}