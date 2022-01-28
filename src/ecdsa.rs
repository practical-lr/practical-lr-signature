use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use sha2::Sha512;

use super::{aggregate_curve25519, sample_curve25519_lambda, hash_tilde_curve25519, curve25519_scalar_list_to_bytes};

pub fn keygen(n: usize) -> (Vec<Scalar>, RistrettoPoint) {
    let sk = sample_curve25519_lambda(n);
    let a_list = hash_tilde_curve25519(&curve25519_scalar_list_to_bytes(&sk), n, false);
    let pk = RISTRETTO_BASEPOINT_POINT * aggregate_curve25519(&a_list, &sk);
    (sk, pk)
}

pub fn sign(sk: &[Scalar], msg: &[u8]) -> (Scalar, Scalar) {
    let n = sk.len();
    let msg_hash = Scalar::hash_from_bytes::<Sha512>(msg);
    let a_list = hash_tilde_curve25519(&curve25519_scalar_list_to_bytes(&sk), n, false);
    let k_list = sample_curve25519_lambda(n);
    let b_list = hash_tilde_curve25519(&curve25519_scalar_list_to_bytes(&k_list), n, true);
    let point = RISTRETTO_BASEPOINT_POINT * aggregate_curve25519(&b_list, &k_list);
    let r = Scalar::from_bytes_mod_order(point.compress().to_bytes());
    let s = aggregate_curve25519(&b_list, &k_list).invert();
    let s = s * (msg_hash + r * aggregate_curve25519(&a_list, &sk));
    (r, s)
}

pub fn verify(pk: &RistrettoPoint, msg: &[u8], signature: &(Scalar, Scalar)) -> bool {
    let (r, s) = signature;
    let msg_hash = Scalar::hash_from_bytes::<Sha512>(msg);
    let point = (RISTRETTO_BASEPOINT_POINT * msg_hash + pk * r) * s.invert();
    r == &Scalar::from_bytes_mod_order(point.compress().to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_lr_ecdsa() {
        let n = 100;
        let msg = "Hello, world!";
        let (sk, pk) = keygen(n);
        let signature = sign(&sk, &msg.as_bytes());
        assert!(verify(&pk, &msg.as_bytes(), &signature))
    }
}