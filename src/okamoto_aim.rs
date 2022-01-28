use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use sha2::{Digest, Sha512};

use super::{aggregate_curve25519, sample_curve25519_lambda, hash_tilde_curve25519, curve25519_scalar_list_to_bytes};

lazy_static::lazy_static! {
    static ref BASE_POINT2: RistrettoPoint = {
        let mut rng = rand::rngs::ThreadRng::default();
        RistrettoPoint::random(&mut rng)
    };
}

pub fn keygen(n: usize) -> (Vec<Scalar>, RistrettoPoint) {
    let sk = sample_curve25519_lambda(n);
    let mut sk_hash = curve25519_scalar_list_to_bytes(&sk);
    sk_hash.push(0);
    let a_list = hash_tilde_curve25519(&sk_hash, n, false);
    *sk_hash.last_mut().unwrap() = 1;
    let b_list = hash_tilde_curve25519(&sk_hash, n, false);
    let pk = RISTRETTO_BASEPOINT_POINT * aggregate_curve25519(&a_list, &sk) + *BASE_POINT2 * aggregate_curve25519(&b_list, &sk);
    (sk, pk)
}

pub fn sign(pk: &RistrettoPoint, sk: &[Scalar], msg: &[u8]) -> (Scalar, Scalar, Scalar) {
    let n = sk.len();
    let msg_hash = Scalar::hash_from_bytes::<Sha512>(msg);

    let mut sk_hash = curve25519_scalar_list_to_bytes(&sk);
    sk_hash.push(0);
    let a_list = hash_tilde_curve25519(&sk_hash, n, false);
    *sk_hash.last_mut().unwrap() = 1;
    let b_list = hash_tilde_curve25519(&sk_hash, n, false);

    let r_list = sample_curve25519_lambda(n);
    let mut r_hash = curve25519_scalar_list_to_bytes(&r_list);
    r_hash.push(0);
    let d_list = hash_tilde_curve25519(&r_hash, n, false);
    *r_hash.last_mut().unwrap() = 1;
    let e_list = hash_tilde_curve25519(&r_hash, n, false);

    let r_point = RISTRETTO_BASEPOINT_POINT *aggregate_curve25519(&d_list, &r_list) + *BASE_POINT2 * aggregate_curve25519(&e_list, &r_list);

    let mut c_hash = Sha512::default();
    c_hash.update(pk.compress().as_bytes());
    c_hash.update(msg_hash.as_bytes());
    c_hash.update(r_point.compress().as_bytes());
    let c = Scalar::from_hash::<Sha512>(c_hash);

    let z_1 = aggregate_curve25519(&d_list, &r_list) + c * aggregate_curve25519(&a_list, &sk);
    let z_2 = aggregate_curve25519(&e_list, &r_list) + c * aggregate_curve25519(&b_list, &sk);

    (c, z_1, z_2)
}

pub fn verify(pk: &RistrettoPoint, msg: &[u8], signature: &(Scalar, Scalar, Scalar)) -> bool {
    let (c, z_1, z_2) = signature;
    let msg_hash = Scalar::hash_from_bytes::<Sha512>(msg);

    let mut c_candidate_hash = Sha512::default();
    c_candidate_hash.update(pk.compress().as_bytes());
    c_candidate_hash.update(msg_hash.as_bytes());
    let r_point = RISTRETTO_BASEPOINT_POINT * z_1 + *BASE_POINT2 * z_2;
    let r_point = r_point - pk * c;
    c_candidate_hash.update(r_point.compress().as_bytes());

    c == &Scalar::from_hash::<Sha512>(c_candidate_hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_lr_okamoto_aim() {
        let n = 100;
        let msg = "Hello, world!";
        let (sk, pk) = keygen(n);
        let signature = sign(&pk, &sk, &msg.as_bytes());
        assert!(verify(&pk, &msg.as_bytes(), &signature))
    }
}