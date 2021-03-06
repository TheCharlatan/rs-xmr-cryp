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

const RINGSIZE: usize = 10;

fn ristretto_point_hash(point: ristretto::RistrettoPoint) -> ristretto::RistrettoPoint {
    let point_bytes: [u8; 32] = point.compress().to_bytes();
    let hash_point = ristretto::RistrettoPoint::hash_from_bytes::<Keccak512>(&point_bytes);
    hash_point
}

fn ristretto_ring_point_hash(ristretto_public_ring: [ristretto::RistrettoPoint; RINGSIZE]) -> ristretto::RistrettoPoint {
    let mut point_bytes: [u8; 32*RINGSIZE] = [0u8; 32*RINGSIZE];
    for i in 0..RINGSIZE {
        for j in 0..32 {
            point_bytes[i*j] = ristretto_public_ring[i].compress().to_bytes()[j];
        }
    }
    ristretto::RistrettoPoint::hash_from_bytes::<Keccak512>(&point_bytes)
}

fn challenge_hash(
        ristretto_public_ring: [ristretto::RistrettoPoint; RINGSIZE],
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
    let hash_point_bytes: [u8; 32] = hasher.result().as_slice().try_into().expect("wrong length");
    scalar::Scalar::from_bytes_mod_order(hash_point_bytes)
}

fn ring_sig(
        _index: i32,
        message: [u8; 32],
        secret: scalar::Scalar,
        ristretto_public_ring: [ristretto::RistrettoPoint; RINGSIZE]) -> (scalar::Scalar, [scalar::Scalar; RINGSIZE], ristretto::RistrettoPoint) {
    let G = constants::RISTRETTO_BASEPOINT_POINT;
    let mut _dummy_secret =  [0u8; 64];
    OsRng.fill_bytes(&mut _dummy_secret);
    let ring_point_hash = ristretto_ring_point_hash(ristretto_public_ring);
    let key_image = secret * ring_point_hash;
    let alpha = scalar::Scalar::from_bytes_mod_order_wide(&[OsRng.next_u64() as u8; 64]);
    let alpha_point = alpha * G;
    let alpha_image = alpha * ristretto_ring_point_hash(ristretto_public_ring);
    let mut challenges: [scalar::Scalar; RINGSIZE] = [scalar::Scalar::from_bytes_mod_order([0u8; 32]); RINGSIZE];
    let mut responses: [scalar::Scalar; RINGSIZE] = [scalar::Scalar::from_bytes_mod_order_wide(&[OsRng.next_u64() as u8; 64]); RINGSIZE];
    challenges[1] = challenge_hash(ristretto_public_ring, message, key_image, alpha_point, alpha_image);
    for i in 2..RINGSIZE {
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
        responses: [scalar::Scalar; RINGSIZE],
        ristretto_public_ring: [ristretto::RistrettoPoint; RINGSIZE],
        key_image: ristretto::RistrettoPoint) {
    // check for shenanigans against the key image
    if constants::BASEPOINT_ORDER * key_image != ristretto::RistrettoPoint::from_uniform_bytes(&[0u8;64]) {
        panic!();
    }
    let G = constants::RISTRETTO_BASEPOINT_POINT;
    let ring_point_hash = ristretto_ring_point_hash(ristretto_public_ring);
    let mut challenges: [scalar::Scalar; RINGSIZE] = [scalar::Scalar::from_bytes_mod_order([0u8; 32]); RINGSIZE];
    challenges[0] = challenge;

    for i in 0..9 {
        let verification_point = responses[i] * G + challenges[i] * ristretto_public_ring[i];
        let verification_image = responses[i] * ring_point_hash + challenges[i] * key_image;
        challenges[i+1] = challenge_hash(ristretto_public_ring, message, key_image, verification_point, verification_image);
    }
    let verification_point = responses[9] * G + challenges[9] * ristretto_public_ring[9];
    let verification_image = responses[9] * ring_point_hash + challenges[9] * key_image;
    challenges[0] = challenge_hash(ristretto_public_ring, message, key_image, verification_point, verification_image);
    // check that the ring has indeed been closed
    if challenges[0] != challenge {
        panic!();
    }
    println!("{:?} == {:?}", challenges[0], challenge)
}

fn main() {
    let G = constants::RISTRETTO_BASEPOINT_POINT;
    let message: [u8; 32] = [0u8; 32];
    let ristretto_secret_ring: [scalar::Scalar; RINGSIZE] = [scalar::Scalar::from_bytes_mod_order_wide(&[OsRng.next_u64() as u8; 64]); RINGSIZE];
    let mut ristretto_public_ring: [ristretto::RistrettoPoint; RINGSIZE] = [ristretto::RistrettoPoint::from_uniform_bytes(&[0u8;64]); RINGSIZE];
    for i in 0..RINGSIZE {
        ristretto_public_ring[i] = ristretto_secret_ring[i] * G;
    }
    let (challenge, responses, key_image) = ring_sig(0, message, ristretto_secret_ring[0], ristretto_public_ring);
    ring_sig_verify(message, challenge, responses, ristretto_public_ring, key_image);
}

