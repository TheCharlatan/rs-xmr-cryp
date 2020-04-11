#![allow(non_snake_case)]

extern crate rand_core;
use rand_core::{OsRng, RngCore};

extern crate curve25519_dalek;
extern crate ed25519_dalek;
use curve25519_dalek::constants;
use curve25519_dalek::ristretto;
use curve25519_dalek::scalar;

extern crate sha3;
use sha3::{Digest, Keccak256, Keccak512};

use std::convert::TryInto;

pub const RINGSIZE: usize = 3;
pub const G: ristretto::RistrettoPoint = constants::RISTRETTO_BASEPOINT_POINT;

pub fn ristretto_point_hash(point: ristretto::RistrettoPoint) -> ristretto::RistrettoPoint {
    let point_bytes: [u8; 32] = point.compress().to_bytes();
    let hash_point = ristretto::RistrettoPoint::hash_from_bytes::<Keccak512>(&point_bytes);
    hash_point
}

pub fn random_scalar() -> scalar::Scalar {
    return scalar::Scalar::from_bytes_mod_order_wide(&[OsRng.next_u64() as u8; 64]);
}

fn aggregate_hash(
    index: u8,
    public_ring: [ristretto::RistrettoPoint; RINGSIZE],
    key_image: ristretto::RistrettoPoint,
    amount_ring: [ristretto::RistrettoPoint; RINGSIZE],
    amount_image: ristretto::RistrettoPoint,
    timelock_ring: [ristretto::RistrettoPoint; RINGSIZE],
    timelock_image: ristretto::RistrettoPoint,
) -> scalar::Scalar {
    let mut hasher = Keccak256::new();
    hasher.input([index]);
    for pubkey in public_ring.iter() {
        hasher.input(pubkey.compress().to_bytes());
    }
    hasher.input(key_image.compress().to_bytes());
    for pubkey in amount_ring.iter() {
        hasher.input(pubkey.compress().to_bytes());
    }
    hasher.input(amount_image.compress().to_bytes());
    for pubkey in timelock_ring.iter() {
        hasher.input(pubkey.compress().to_bytes());
    }
    hasher.input(timelock_image.compress().to_bytes());

    let aggregate_hash_bytes: [u8; 32] =
        hasher.result().as_slice().try_into().expect("wrong length");
    scalar::Scalar::from_bytes_mod_order(aggregate_hash_bytes)
}

fn challenge_hash(
    public_ring: [ristretto::RistrettoPoint; RINGSIZE],
    amount_ring: [ristretto::RistrettoPoint; RINGSIZE],
    timelock_ring: [ristretto::RistrettoPoint; RINGSIZE],
    message: [u8; 32],
    L: ristretto::RistrettoPoint,
    R: ristretto::RistrettoPoint,
) -> scalar::Scalar {
    let mut hasher = Keccak256::new();
    for pubkey in public_ring.iter() {
        hasher.input(pubkey.compress().to_bytes());
    }
    for pubkey in amount_ring.iter() {
        hasher.input(pubkey.compress().to_bytes());
    }
    for pubkey in timelock_ring.iter() {
        hasher.input(pubkey.compress().to_bytes());
    }
    hasher.input(message);
    hasher.input(L.compress().to_bytes());
    hasher.input(R.compress().to_bytes());
    let challenge_hash_bytes: [u8; 32] = hasher.result().as_slice().try_into().expect("wrong length");
    scalar::Scalar::from_bytes_mod_order(challenge_hash_bytes)
}

pub fn clsag_sign(
    privkey_index: usize,
    message: [u8; 32],
    privkey: scalar::Scalar,
    public_ring: [ristretto::RistrettoPoint; RINGSIZE],
    amount_privkey: scalar::Scalar,
    amount_ring: [ristretto::RistrettoPoint; RINGSIZE],
    timelock_privkey: scalar::Scalar,
    timelock_ring: [ristretto::RistrettoPoint; RINGSIZE],
) -> (
    scalar::Scalar,
    [scalar::Scalar; RINGSIZE],
    ristretto::RistrettoPoint,
    ristretto::RistrettoPoint,
    ristretto::RistrettoPoint,
) {
    // construct key images
    let privkey_image = ristretto_point_hash(public_ring[privkey_index]) * privkey;
    let amount_image = ristretto_point_hash(public_ring[privkey_index]) * amount_privkey;
    let timelock_image = ristretto_point_hash(public_ring[privkey_index]) * timelock_privkey;

    //construct challenges
    let mu_privkey = aggregate_hash(
        0, // has domain separator
        public_ring,
        privkey_image,
        amount_ring,
        amount_image,
        timelock_ring,
        timelock_image,
    );
    let mu_amount = aggregate_hash(
        1,
        public_ring,
        privkey_image,
        amount_ring,
        amount_image,
        timelock_ring,
        timelock_image,
    );
    let mu_timelock = aggregate_hash(
        2,
        public_ring,
        privkey_image,
        amount_ring,
        amount_image,
        timelock_ring,
        timelock_image,
    );

    let alpha = random_scalar();
    let mut challenges: [scalar::Scalar; RINGSIZE] =
        [scalar::Scalar::from_bytes_mod_order_wide(&[0u8; 64]); RINGSIZE];
    let mut s: [scalar::Scalar; RINGSIZE] = [random_scalar(); RINGSIZE];

    // generate "critical" (our) ring element
    let mut R = alpha * ristretto_point_hash(public_ring[privkey_index]);
    let mut L = alpha * G;
    challenges[((privkey_index + 1) % RINGSIZE)] =
        challenge_hash(public_ring, amount_ring, timelock_ring, message, L, R);

    // generate the ring
    for mut i in (privkey_index + 1) .. (privkey_index + RINGSIZE) {
        i = i % RINGSIZE;
        L = s[i] * G
            + (challenges[i] * mu_privkey) * public_ring[i]
            + (challenges[i] * mu_amount) * amount_ring[i]
            + (challenges[i] * mu_timelock) * timelock_ring[i];
        R = s[i] * ristretto_point_hash(public_ring[i])
            + (challenges[i] * mu_privkey) * privkey_image
            + (challenges[i] * mu_amount) * amount_image
            + (challenges[i] * mu_timelock) * timelock_image;
        challenges[(i + 1) % RINGSIZE] = challenge_hash(public_ring, amount_ring, timelock_ring, message, L, R);
    }

    // close the ring and return the signature data
    s[privkey_index] = alpha
        - challenges[privkey_index]
            * (mu_privkey * privkey + mu_amount * amount_privkey + mu_timelock * timelock_privkey);
    (challenges[0], s, privkey_image, amount_image, timelock_image)
}

pub fn clsag_verify(
    message: [u8; 32],
    public_ring: [ristretto::RistrettoPoint; RINGSIZE],
    amount_ring: [ristretto::RistrettoPoint; RINGSIZE],
    timelock_ring: [ristretto::RistrettoPoint; RINGSIZE],
    challenge_0: scalar::Scalar,
    s: [scalar::Scalar; RINGSIZE],
    privkey_image: ristretto::RistrettoPoint,
    amount_image: ristretto::RistrettoPoint,
    timelock_image: ristretto::RistrettoPoint,
) {
    // initialize the ring structure
    let mut challenges: [scalar::Scalar; RINGSIZE] =
        [scalar::Scalar::from_bytes_mod_order_wide(&[0u8; 64]); RINGSIZE];
    challenges[0] = challenge_0;

    // initalize the challenges
    let mu_privkey = aggregate_hash(
        0,
        public_ring,
        privkey_image,
        amount_ring,
        amount_image,
        timelock_ring,
        timelock_image,
    );
    let mu_amount = aggregate_hash(
        1,
        public_ring,
        privkey_image,
        amount_ring,
        amount_image,
        timelock_ring,
        timelock_image,
    );
    let mu_timelock = aggregate_hash(
        2,
        public_ring,
        privkey_image,
        amount_ring,
        amount_image,
        timelock_ring,
        timelock_image,
    );

    // generate the ring
    for i in 0..RINGSIZE {
        let L = s[i] * G
            + (challenges[i] * mu_privkey) * public_ring[i]
            + (challenges[i] * mu_amount) * amount_ring[i]
            + (challenges[i] * mu_timelock) * timelock_ring[i];
        let R = s[i] * ristretto_point_hash(public_ring[i])
            + (challenges[i] * mu_privkey) * privkey_image
            + (challenges[i] * mu_amount) * amount_image
            + (challenges[i] * mu_timelock) * timelock_image;
        challenges[(i + 1) % RINGSIZE] = challenge_hash(public_ring, amount_ring, timelock_ring, message, L, R);
    }

    // verify that the ring is closed
    if challenges[0] != challenge_0 {
        print!("Incoming: {:?}\n outgoing: {:?}]\n", challenge_0.to_bytes(), challenges[0].to_bytes());
        panic!();
    }
}
