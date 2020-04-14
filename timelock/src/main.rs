#![allow(non_snake_case)]

extern crate rand;
use rand::Rng;

extern crate curve25519_dalek;
extern crate ed25519_dalek;
use curve25519_dalek::ristretto;
use curve25519_dalek::scalar;

extern crate bulletproofs;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};

extern crate merlin;
use merlin::Transcript;

mod clsag;
use clsag::{Signature, clsag_sign, clsag_verify};

mod rct_utils;
use rct_utils::{random_point, H, random_scalar, G, RINGSIZE, u64_to_32_bytes_u8_array, bytes_u8_array_to_u64};

const BITS: usize = 4;

struct Bulletproof {
    proof: RangeProof,
    committed_value: ristretto::CompressedRistretto,
}

struct Input {
    ring_member_offsets: [u8; RINGSIZE],
    // contains challenge, responses and key images
    signature: Signature,
    pseudo_amount_commitment: ristretto::RistrettoPoint,
}

struct Output {
    one_time_privkey: scalar::Scalar,
    one_time_pubkey: ristretto::RistrettoPoint,
    amount_commitment: ristretto::RistrettoPoint,
    amount: u64,
    amount_blind: scalar::Scalar,
    range_proof: Bulletproof,
}

struct Transaction {
    // first follow the things available to the verifier
    fee: u64,
    inputs: Vec<Input>,
    outputs: Vec<Output>,
    // then what is available to the signer
    locktime: u64, 
    locktime_blind: scalar::Scalar,
    locktime_commitment: ristretto::RistrettoPoint,
    pseudo_locktime_commitment: ristretto::RistrettoPoint,
}

fn generate_fake_tx() -> Transaction {
    let bp_gens = BulletproofGens::new(64, 1);
    let pc_gens = PedersenGens::default();
    let secret_value = 1037578891u64;
    let mut prover_transcript = Transcript::new(b"locktime example");
    let (proof, committed_value) = RangeProof::prove_single(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        secret_value,
        &random_scalar(),
        32,
    )
    .expect("I promise this will totally never fail");

    let privkey = random_scalar();
    let amount = 10;
    let amount_blind = random_scalar();
    let locktime = 10;
    let locktime_blind = random_scalar();
    let input = Input {
        ring_member_offsets: [0u8; RINGSIZE],
        signature: Signature {
            challenge_0: random_scalar(),
            s: [random_scalar(); RINGSIZE],
            privkey_image: random_point(),
            amount_image: random_point(),
            locktime_image: random_point(),
        },
        pseudo_amount_commitment: random_point(),
    };
    let output = Output {
        one_time_pubkey: privkey * G,
        one_time_privkey: privkey,
        amount_commitment: scalar::Scalar::from_bytes_mod_order(u64_to_32_bytes_u8_array(amount)) * H() + amount_blind * G,
        amount: amount,
        amount_blind: amount_blind,
        range_proof: Bulletproof {
            proof: proof,
            committed_value: committed_value,
        },
    };

    Transaction {
        fee: 1,
        locktime: locktime,
        locktime_blind: locktime_blind,
        pseudo_locktime_commitment: random_point(),
        locktime_commitment: scalar::Scalar::from_bytes_mod_order(u64_to_32_bytes_u8_array(locktime))* H() + locktime_blind * G,
        inputs: vec![input],
        outputs: vec![output],
    }
}

fn main() {
    // initialize fake tx vector
    let mut fake_txs: Vec<Transaction> = Vec::new();
    for _ in 0..20 {
        fake_txs.push(generate_fake_tx());
    }

    let mut tx_ring: Vec<Transaction> = Vec::new();

    // compute ring offsets
    let mut ring_member_offsets: [u8; RINGSIZE] = [0u8; RINGSIZE];
    let mut i = 0usize;
    while i < RINGSIZE {
        let tx_offset = rand::thread_rng().gen_range(0, fake_txs.len() as u8);
        if !(ring_member_offsets.contains(&(tx_offset))) {
            ring_member_offsets[i] = tx_offset;
            i+= 1;
        }
    }

    // data collection
    let current_time = scalar::Scalar::from_bytes_mod_order(u64_to_32_bytes_u8_array(20u64));
    let privkey_index = rand::thread_rng().gen_range(0, RINGSIZE);
    let message: [u8; 32] = [0u8; 32];

    // signing tx keys
    let mut privkey = random_scalar();
    let mut amount_blind = random_scalar();
    let mut locktime_blind = random_scalar();
    let mut amount = random_scalar();
    let mut locktime = random_scalar();
    let mut public_ring: [ristretto::RistrettoPoint; RINGSIZE] = [random_point(); RINGSIZE];
    let mut amount_ring: [ristretto::RistrettoPoint; RINGSIZE] = [random_point(); RINGSIZE];
    let mut locktime_ring: [ristretto::RistrettoPoint; RINGSIZE] = [random_point(); RINGSIZE];
    let mut j = 0;
    for index in ring_member_offsets.iter() {
        let i = *index as usize;
        let transaction = &fake_txs[i];
        public_ring[j] = transaction.outputs[0].one_time_pubkey;
        amount_ring[j] = transaction.outputs[0].amount_commitment;
        locktime_ring[j] = transaction.locktime_commitment; 
        j += 1;
        if j == privkey_index {
            privkey = transaction.outputs[0].one_time_privkey;
            amount_blind = transaction.outputs[0].amount_blind;
            locktime_blind = transaction.locktime_blind;
            amount = scalar::Scalar::from_bytes_mod_order(u64_to_32_bytes_u8_array(transaction.outputs[0].amount));
            locktime = scalar::Scalar::from_bytes_mod_order(u64_to_32_bytes_u8_array(transaction.locktime));
        }
    }

    // locktime commitment keys
    //let locktime = scalar::Scalar::from_bytes_mod_order([4u8; 32]);
    //let locktime_blind = random_scalar();
    //let mut locktime_ring: [ristretto::RistrettoPoint; RINGSIZE] = [random_point(); RINGSIZE];
    //locktime_ring[privkey_index] = locktime * H() + locktime_blind * G;
    // choose an auxiliary amount in the locktime
    let amount_aux = scalar::Scalar::from_bytes_mod_order(u64_to_32_bytes_u8_array(4));

    //// choose an auxiliary time in the locktime
    let locktime_aux = scalar::Scalar::from_bytes_mod_order([6u8; 32]);
    let locktime_diff_blind = random_scalar();
    let locktime_diff = (locktime_aux - locktime) * H() + (locktime_diff_blind * G);

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
        &locktime_diff_blind,
        32,
    )
    .expect("I promise this will totally never fail");

    // generate CLSAG signature
    let mut sig_locktime_ring: [ristretto::RistrettoPoint; RINGSIZE] = [random_point(); RINGSIZE];
    for i in 0..RINGSIZE {
        sig_locktime_ring[i] = (locktime_ring[i] + locktime_diff) - locktime_aux * H()
    }

    // sign it
    let signature: Signature = clsag_sign(
        privkey_index,
        message,
        privkey,
        public_ring,
        amount_blind,
        amount_ring,
        locktime_blind + locktime_diff_blind,
        sig_locktime_ring,
    );

    clsag_verify(
        message,
        public_ring,
        amount_ring,
        sig_locktime_ring,
        signature,
    );

    let mut verifier_transcript = Transcript::new(b"locktime example");
    assert!(
        proof
            .verify_single(&bp_gens, &pc_gens, &mut verifier_transcript, &committed_value, 32)
            .is_ok()
    );
}
