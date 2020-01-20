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
        response_image: ristretto::RistrettoPoint) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    for pubkey in ristretto_public_ring.iter() {
        hasher.input(pubkey.compress().to_bytes());
    }
    hasher.input(message);
    hasher.input(key_image.compress().to_bytes());
    hasher.input(response_point.compress().to_bytes());
    hasher.input(response_image.compress().to_bytes());
    let mut hash_point_bytes: [u8; 32] = hasher.result().as_slice().try_into().expect("wrong length");
    hash_point_bytes
}

fn ring_sig(message: [u8; 32], secret: scalar::Scalar, ristretto_public_ring: [ristretto::RistrettoPoint; 10]) {
    let G = constants::RISTRETTO_BASEPOINT_POINT;
    let mut _secret =  [0u8; 64];
    OsRng.fill_bytes(&mut _secret);
    let ring_point_hash = ristretto_ring_point_hash(ristretto_public_ring);
    let key_image = secret * ring_point_hash;
    let ring_alpha = scalar::Scalar::from_bytes_mod_order_wide(&[OsRng.next_u64() as u8; 64]);
    let response_ring: [scalar::Scalar; 10] = [scalar::Scalar::from_bytes_mod_order_wide(&[OsRng.next_u64() as u8; 64]); 10];
    let alpha_point = ring_alpha * G;
    let alpha_image = ring_alpha * ristretto_ring_point_hash(ristretto_public_ring);
    let c_1 = challenge_hash(ristretto_public_ring, message, key_image, alpha_point, alpha_image);
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
    ring_sig(message, ristretto_secret_ring[0], ristretto_public_ring);
}


