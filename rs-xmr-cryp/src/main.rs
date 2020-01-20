extern crate rand_core;
extern crate ed25519_dalek;
extern crate curve25519_dalek;
extern crate sha3;

use std::convert::TryInto;
use rand_core::{OsRng, RngCore};
use curve25519_dalek::constants;
use curve25519_dalek::scalar;
use curve25519_dalek::ristretto;
use sha3::{Digest, Keccak512, Keccak256};

fn ristretto_point_hash(point: ristretto::RistrettoPoint) -> ristretto::RistrettoPoint {
    let point_bytes: [u8; 32] = point.compress().to_bytes();
    let hash_point = ristretto::RistrettoPoint::hash_from_bytes::<Keccak512>(&point_bytes);
    hash_point
}

fn ristretto_ring_point_hash(ristretto_public_ring: [ristretto::RistrettoPoint; 10]) -> ristretto::RistrettoPoint {
    let mut point_bytes: [u8; 32*10] = [0u8; 32*10];
    for i in 0..10 {
        for j in 0..32 {
            point_bytes[i*j] = ristretto_public_ring[i].compress().to_bytes()[j];
        }
    }
    ristretto::RistrettoPoint::hash_from_bytes::<Keccak512>(&point_bytes)
}

fn challenge_hash(
        ristretto_public_ring: [ristretto::RistrettoPoint; 10],
        message: [u8; 32],
        key_image: ristretto::RistrettoPoint,
        response_point: ristretto::RistrettoPoint,
        response_image: ristretto::RistrettoPoint) -> scalar::Scalar {
    let mut hasher = Keccak256::new();
    for pubkey in ristretto_public_ring.iter() {
        hasher.input(pubkey.compress().to_bytes());
    }
    hasher.input(message);
    hasher.input(key_image.compress().to_bytes());
    hasher.input(response_point.compress().to_bytes());
    hasher.input(response_image.compress().to_bytes());
    let mut hash_point_bytes: [u8; 32] = hasher.result().as_slice().try_into().expect("wrong length");
    scalar::Scalar::from_bytes_mod_order(hash_point_bytes)
}

fn ring_sig(
        index: i32,
        message: [u8; 32],
        secret: scalar::Scalar,
        ristretto_public_ring: [ristretto::RistrettoPoint; 10]) -> (scalar::Scalar, [scalar::Scalar; 10], ristretto::RistrettoPoint) {
    let G = constants::RISTRETTO_BASEPOINT_POINT;
    let mut _dummy_secret =  [0u8; 64];
    OsRng.fill_bytes(&mut _dummy_secret);
    let ring_point_hash = ristretto_ring_point_hash(ristretto_public_ring);
    let key_image = secret * ring_point_hash;
    let alpha = scalar::Scalar::from_bytes_mod_order_wide(&[OsRng.next_u64() as u8; 64]);
    let alpha_point = alpha * G;
    let alpha_image = alpha * ristretto_ring_point_hash(ristretto_public_ring);
    let mut challenges: [scalar::Scalar; 10] = [scalar::Scalar::from_bytes_mod_order([0u8; 32]); 10];
    let mut responses: [scalar::Scalar; 10] = [scalar::Scalar::from_bytes_mod_order_wide(&[OsRng.next_u64() as u8; 64]); 10];
    challenges[1] = challenge_hash(ristretto_public_ring, message, key_image, alpha_point, alpha_image);
    for i in 2..10 {
        let response_point = responses[i-1] * G + challenges[i-1] * ristretto_public_ring[i-1];
        let response_image = responses[i-1] * ring_point_hash + challenges[i-1] * key_image;
        challenges[i] = challenge_hash(ristretto_public_ring, message, key_image, response_point, response_image);
    }
    let response_point = responses[9] * G + challenges[9] * ristretto_public_ring[9];
    let response_image = responses[9] * ring_point_hash + challenges[9] * key_image;
    challenges[0] = challenge_hash(ristretto_public_ring, message, key_image, response_point, response_image);
    responses[0] = alpha - challenges[0] * secret;
    return (challenges[0], responses, key_image)
}

fn ring_sig_verify(
        message: [u8; 32],
        challenge: scalar::Scalar,
        responses: [scalar::Scalar; 10],
        ristretto_public_ring: [ristretto::RistrettoPoint; 10],
        key_image: ristretto::RistrettoPoint) {
    let G = constants::RISTRETTO_BASEPOINT_POINT;
    let ring_point_hash = ristretto_ring_point_hash(ristretto_public_ring);
    let mut challenges: [scalar::Scalar; 10] = [scalar::Scalar::from_bytes_mod_order([0u8; 32]); 10];
    challenges[0] = challenge;

    for i in 0..9 {
        let verification_point = responses[i] * G + challenges[i] * ristretto_public_ring[i];
        let verification_image = responses[i] * ring_point_hash + challenges[i] * key_image;
        challenges[i+1] = challenge_hash(ristretto_public_ring, message, key_image, verification_point, verification_image);
    }
    let verification_point = responses[9] * G + challenges[9] * ristretto_public_ring[9];
    let verification_image = responses[9] * ring_point_hash + challenges[9] * key_image;
    challenges[0] = challenge_hash(ristretto_public_ring, message, key_image, verification_point, verification_image);
    assert!(challenges[0] == challenge);
    println!("{:?} == {:?}", challenges[0], challenge)
}

fn main() {
    let G_RISTRETTO = constants::RISTRETTO_BASEPOINT_POINT;
    let H  = ristretto_point_hash(G_RISTRETTO);
    let message: [u8; 32] = [0u8; 32];
    let ristretto_secret_ring: [scalar::Scalar; 10] = [scalar::Scalar::from_bytes_mod_order_wide(&[OsRng.next_u64() as u8; 64]); 10];
    let mut ristretto_public_ring: [ristretto::RistrettoPoint; 10] = [ristretto::RistrettoPoint::from_uniform_bytes(&[0u8;64]); 10];
    for i in 0..10 {
        ristretto_public_ring[i] = ristretto_secret_ring[i] * G_RISTRETTO;
    }
    let (challenge, responses, key_image) = ring_sig(0, message, ristretto_secret_ring[0], ristretto_public_ring);
    ring_sig_verify(message, challenge, responses, ristretto_public_ring, key_image);
}


