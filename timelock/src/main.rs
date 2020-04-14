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
use rct_utils::{random_point, empty_point, random_scalar, empty_scalar, G, H, RINGSIZE, u64_to_scalar};

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
    locktime_range_proof: Bulletproof,
    locktime_aux: u64,
}

struct Output {
    one_time_privkey: scalar::Scalar,
    one_time_pubkey: ristretto::RistrettoPoint,
    amount_commitment: ristretto::RistrettoPoint,
    amount: u64,
    amount_blind: scalar::Scalar,
    amount_range_proof: Bulletproof,
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
    // these inputs will never be verified or used for anything
    let input = Input {
        ring_member_offsets: [0u8; RINGSIZE],
        signature: Signature {
            challenge_0: empty_scalar(),
            s: [empty_scalar(); RINGSIZE],
            privkey_image: empty_point(),
            amount_image: empty_point(),
            locktime_image: empty_point(),
        },
        pseudo_amount_commitment: empty_point(),
        locktime_range_proof:Bulletproof {
            proof: proof,
            committed_value: committed_value,
        },
        locktime_aux: 0,
    };
    let (proof, committed_value) = RangeProof::prove_single(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        secret_value,
        &random_scalar(),
        32,
    )
    .expect("I promise this will totally never fail");

    let output = Output {
        one_time_pubkey: privkey * G,
        one_time_privkey: privkey,
        amount_commitment: u64_to_scalar(amount) * H() + amount_blind * G,
        amount: amount,
        amount_blind: amount_blind,
        amount_range_proof: Bulletproof {
            proof: proof,
            committed_value: committed_value,
        },
    };

    Transaction {
        fee: 1,
        locktime: locktime,
        locktime_blind: locktime_blind,
        pseudo_locktime_commitment: random_point(),
        locktime_commitment: u64_to_scalar(locktime) * H() + locktime_blind * G,
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
    let privkey_index = rand::thread_rng().gen_range(0, RINGSIZE);
    let message: [u8; 32] = [0u8; 32];

    // signing tx keys
    let mut privkey = empty_scalar();
    let mut input_amount_blind = empty_scalar();
    let mut input_locktime_blind = empty_scalar();
    let mut input_amount = empty_scalar();
    let mut input_locktime = empty_scalar();
    let mut public_ring: [ristretto::RistrettoPoint; RINGSIZE] = [empty_point(); RINGSIZE];
    let mut input_amount_ring: [ristretto::RistrettoPoint; RINGSIZE] = [empty_point(); RINGSIZE];
    let mut input_locktime_ring: [ristretto::RistrettoPoint; RINGSIZE] = [empty_point(); RINGSIZE];
    let mut j = 0;
    for index in ring_member_offsets.iter() {
        let i = *index as usize;
        let transaction = &fake_txs[i];
        public_ring[j] = transaction.outputs[0].one_time_pubkey;
        input_amount_ring[j] = transaction.outputs[0].amount_commitment;
        input_locktime_ring[j] = transaction.locktime_commitment;
        if j == privkey_index {
            privkey = transaction.outputs[0].one_time_privkey;
            input_amount_blind = transaction.outputs[0].amount_blind;
            input_locktime_blind = transaction.locktime_blind;
            input_amount = u64_to_scalar(transaction.outputs[0].amount);
            input_locktime = u64_to_scalar(transaction.locktime);
        }
        j += 1;
    }

    // generate amount pseudo commitment and ring as will be used in the signature and transaction input
    let input_amount_pseudo_blind = random_scalar();
    let input_amount_pseudo_commitment = input_amount * H() + input_amount_pseudo_blind * G;
    let mut input_amount_pseudo_ring: [ristretto::RistrettoPoint; RINGSIZE] = [random_point(); RINGSIZE];
    for i in 0..RINGSIZE {
        input_amount_pseudo_ring[i] = input_amount_ring[i] - input_amount_pseudo_commitment;
    }

    // choose an auxiliary time in the locktime
    let locktime_aux = u64_to_scalar(6u64);
    let locktime_diff_blind = random_scalar();
    let locktime_diff = (locktime_aux - input_locktime) * H() + (locktime_diff_blind * G);
    
    // generate pseudo output commitments
    let mut sig_locktime_ring: [ristretto::RistrettoPoint; RINGSIZE] = [random_point(); RINGSIZE];
    for i in 0..RINGSIZE {
        sig_locktime_ring[i] = (input_locktime_ring[i] + locktime_diff) - locktime_aux * H()
    }

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
    // sign it
    let signature: Signature = clsag_sign(
        privkey_index,
        message,
        privkey,
        public_ring,
        input_amount_blind - input_amount_pseudo_blind,
        input_amount_pseudo_ring,
        input_locktime_blind + locktime_diff_blind,
        sig_locktime_ring,
    );

    clsag_verify(
        message,
        public_ring,
        input_amount_pseudo_ring,
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
