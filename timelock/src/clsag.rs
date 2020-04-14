#![allow(non_snake_case)]

extern crate curve25519_dalek;
extern crate ed25519_dalek;
use curve25519_dalek::{ristretto, scalar};

extern crate sha3;
use sha3::{Digest, Keccak256};

use std::convert::TryInto;

use crate::rct_utils::{G, RINGSIZE, ristretto_point_hash, random_scalar};

pub struct Signature {
    // first 
    pub challenge_0: scalar::Scalar,
    // random oracle response values
    pub s: [scalar::Scalar; RINGSIZE],
    // key images
    pub privkey_image: ristretto::RistrettoPoint,
    pub amount_image: ristretto::RistrettoPoint,
    pub locktime_image: ristretto::RistrettoPoint,
}

fn aggregate_hash(
    index: u8,
    public_ring: [ristretto::RistrettoPoint; RINGSIZE],
    key_image: ristretto::RistrettoPoint,
    amount_ring: [ristretto::RistrettoPoint; RINGSIZE],
    amount_image: ristretto::RistrettoPoint,
    locktime_ring: [ristretto::RistrettoPoint; RINGSIZE],
    locktime_image: ristretto::RistrettoPoint,
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
    for pubkey in locktime_ring.iter() {
        hasher.input(pubkey.compress().to_bytes());
    }
    hasher.input(locktime_image.compress().to_bytes());

    let aggregate_hash_bytes: [u8; 32] =
        hasher.result().as_slice().try_into().expect("wrong length");
    scalar::Scalar::from_bytes_mod_order(aggregate_hash_bytes)
}

fn challenge_hash(
    public_ring: [ristretto::RistrettoPoint; RINGSIZE],
    amount_ring: [ristretto::RistrettoPoint; RINGSIZE],
    locktime_ring: [ristretto::RistrettoPoint; RINGSIZE],
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
    for pubkey in locktime_ring.iter() {
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
    locktime_privkey: scalar::Scalar,
    locktime_ring: [ristretto::RistrettoPoint; RINGSIZE],
) -> Signature {
    // construct key images
    let privkey_image = ristretto_point_hash(public_ring[privkey_index]) * privkey;
    let amount_image = ristretto_point_hash(public_ring[privkey_index]) * amount_privkey;
    let locktime_image = ristretto_point_hash(public_ring[privkey_index]) * locktime_privkey;

    //construct challenges
    let mu_privkey = aggregate_hash(
        0, // has domain separator
        public_ring,
        privkey_image,
        amount_ring,
        amount_image,
        locktime_ring,
        locktime_image,
    );
    let mu_amount = aggregate_hash(
        1,
        public_ring,
        privkey_image,
        amount_ring,
        amount_image,
        locktime_ring,
        locktime_image,
    );
    let mu_locktime = aggregate_hash(
        2,
        public_ring,
        privkey_image,
        amount_ring,
        amount_image,
        locktime_ring,
        locktime_image,
    );

    let alpha = random_scalar();
    let mut challenges: [scalar::Scalar; RINGSIZE] =
        [scalar::Scalar::from_bytes_mod_order_wide(&[0u8; 64]); RINGSIZE];
    let mut s: [scalar::Scalar; RINGSIZE] = [random_scalar(); RINGSIZE];

    // generate "critical" (our) ring element
    let mut R = alpha * ristretto_point_hash(public_ring[privkey_index]);
    let mut L = alpha * G;
    challenges[((privkey_index + 1) % RINGSIZE)] =
        challenge_hash(public_ring, amount_ring, locktime_ring, message, L, R);

    // generate the ring
    for mut i in (privkey_index + 1) .. (privkey_index + RINGSIZE) {
        i = i % RINGSIZE;
        L = s[i] * G
            + (challenges[i] * mu_privkey) * public_ring[i]
            + (challenges[i] * mu_amount) * amount_ring[i]
            + (challenges[i] * mu_locktime) * locktime_ring[i];
        R = s[i] * ristretto_point_hash(public_ring[i])
            + (challenges[i] * mu_privkey) * privkey_image
            + (challenges[i] * mu_amount) * amount_image
            + (challenges[i] * mu_locktime) * locktime_image;
        challenges[(i + 1) % RINGSIZE] = challenge_hash(public_ring, amount_ring, locktime_ring, message, L, R);
    }

    // close the ring and return the signature data
    s[privkey_index] = alpha
        - challenges[privkey_index]
            * (mu_privkey * privkey + mu_amount * amount_privkey + mu_locktime * locktime_privkey);
    Signature { 
        challenge_0: challenges[0], 
        s: s,
        privkey_image: privkey_image,
        amount_image: amount_image,
        locktime_image: locktime_image,
    }
}

pub fn clsag_verify(
    message: [u8; 32],
    public_ring: [ristretto::RistrettoPoint; RINGSIZE],
    amount_ring: [ristretto::RistrettoPoint; RINGSIZE],
    locktime_ring: [ristretto::RistrettoPoint; RINGSIZE],
    sig: Signature,
) {
    // initialize the ring structure
    let mut challenges: [scalar::Scalar; RINGSIZE] =
        [scalar::Scalar::from_bytes_mod_order_wide(&[0u8; 64]); RINGSIZE];
    challenges[0] = sig.challenge_0;

    // initalize the challenges
    let mu_privkey = aggregate_hash(
        0,
        public_ring,
        sig.privkey_image,
        amount_ring,
        sig.amount_image,
        locktime_ring,
        sig.locktime_image,
    );
    let mu_amount = aggregate_hash(
        1,
        public_ring,
        sig.privkey_image,
        amount_ring,
        sig.amount_image,
        locktime_ring,
        sig.locktime_image,
    );
    let mu_locktime = aggregate_hash(
        2,
        public_ring,
        sig.privkey_image,
        amount_ring,
        sig.amount_image,
        locktime_ring,
        sig.locktime_image,
    );

    // generate the ring
    for i in 0..RINGSIZE {
        let L = sig.s[i] * G
            + (challenges[i] * mu_privkey) * public_ring[i]
            + (challenges[i] * mu_amount) * amount_ring[i]
            + (challenges[i] * mu_locktime) * locktime_ring[i];
        let R = sig.s[i] * ristretto_point_hash(public_ring[i])
            + (challenges[i] * mu_privkey) * sig.privkey_image
            + (challenges[i] * mu_amount) * sig.amount_image
            + (challenges[i] * mu_locktime) * sig.locktime_image;
        challenges[(i + 1) % RINGSIZE] = challenge_hash(public_ring, amount_ring, locktime_ring, message, L, R);
    }

    // verify that the ring is closed
    if challenges[0] != sig.challenge_0 {
        panic!();
    }
}
