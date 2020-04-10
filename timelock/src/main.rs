#![allow(non_snake_case)]

extern crate rand_core;
use rand_core::{OsRng, RngCore};

extern crate rand;
use rand::Rng;

extern crate curve25519_dalek;
extern crate ed25519_dalek;
use curve25519_dalek::ristretto;
use curve25519_dalek::scalar;

extern crate bulletproofs;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};

//extern crate sha3;
//use sha3::{Digest, Keccak512, Keccak256};

extern crate merlin;
use merlin::Transcript;

//use std::convert::TryInto;

mod clsag;
use clsag::{clsag_sign, clsag_verify, random_scalar, ristretto_point_hash, G, RINGSIZE};

const BITS: usize = 4;

fn random_point() -> ristretto::RistrettoPoint {
    return ristretto::RistrettoPoint::from_uniform_bytes(&[OsRng.next_u64() as u8; 64]);
}

fn H() -> ristretto::RistrettoPoint {
    return ristretto_point_hash(G);
}

fn main() {
    // data collection
    let current_time = scalar::Scalar::from_bytes_mod_order([8u8; 32]); // in monero the unlock_time is uint64_t
    let privkey_index = rand::thread_rng().gen_range(0, RINGSIZE);
    let message: [u8; 32] = [0u8; 32];
    // signing tx keys
    let privkey = random_scalar();
    let mut public_ring: [ristretto::RistrettoPoint; RINGSIZE] = [random_point(); RINGSIZE];
    public_ring[privkey_index] = privkey * G;
    // ammount commitment keys
    let amount_privkey = random_scalar();
    let mut amount_ring: [ristretto::RistrettoPoint; RINGSIZE] = [random_point(); RINGSIZE];
    amount_ring[privkey_index] = privkey * G;
    // timelock commitment keys
    let unlock_time = scalar::Scalar::from_bytes_mod_order([4u8; 32]);
    let unlock_time_blind = random_scalar();
    let mut timelock_ring: [ristretto::RistrettoPoint; RINGSIZE] = [random_point(); RINGSIZE];
    timelock_ring[privkey_index] = unlock_time * H() + unlock_time_blind * G;

    // choose an auxiliary time in the timelock
    let unlock_time_aux = scalar::Scalar::from_bytes_mod_order([6u8; 32]);
    let unlock_time_diff_blind = random_scalar();
    let unlock_time_diff = (unlock_time_aux - unlock_time) * H() + (unlock_time_diff_blind * G);

    // generate 64bit range proof
    let bp_gens = BulletproofGens::new(64, 1);
    let pc_gens = PedersenGens::default();
    let secret_value = 1037578891u64;
    let mut prover_transcript = Transcript::new(b"locktime example");
    let (proof, committed_value) = RangeProof::prove_single(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        secret_value,
        &unlock_time_diff_blind,
        32,
    )
    .expect("I promise this will totally never fail");

    // generate CLSAG signature
    let mut sig_timelock_ring: [ristretto::RistrettoPoint; RINGSIZE] = [random_point(); RINGSIZE];
    for i in 0..RINGSIZE {
        sig_timelock_ring[i] = (timelock_ring[i] + unlock_time_diff) - unlock_time_aux * H()
            + unlock_time_diff_blind * G
    }

    // sign it
    let (challenge, responses, key_image, amount_image, timelock_image) = clsag_sign(
        privkey_index,
        message,
        privkey,
        public_ring,
        amount_privkey,
        amount_ring,
        unlock_time_blind + unlock_time_diff_blind,
        sig_timelock_ring,
    );

    clsag_verify(
        message,
        public_ring,
        amount_ring,
        sig_timelock_ring,
        challenge,
        responses,
        key_image,
        amount_image,
        timelock_image,
    );
}
