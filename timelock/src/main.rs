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
use rct_utils::{empty_point, random_scalar, empty_scalar, G, H, RINGSIZE, u64_to_scalar, scalar_to_u64};

struct Input {
    ring_member_offsets: [u8; RINGSIZE],
    // contains challenge, responses and key images
    signature: Signature,
    pseudo_amount_commitment: ristretto::RistrettoPoint,
    pseudo_locktime_commitment: ristretto::RistrettoPoint,
    locktime_range_proof: RangeProof,
    locktime_aux: u64,
}

struct Output {
    // information for verifier
    one_time_privkey: scalar::Scalar,
    one_time_pubkey: ristretto::RistrettoPoint,
    amount_commitment: ristretto::RistrettoPoint,
    amount_range_proof: RangeProof,
    // information for signer
    amount: u64,
    amount_blind: scalar::Scalar,
}

struct Transaction {
    // information for verifier
    // Remove the fee for now
    // fee: u64,
    inputs: Vec<Input>,
    outputs: Vec<Output>,
    locktime_commitment: ristretto::RistrettoPoint,
    // this simulates the block height for now
    transaction_time: u64,
    // information for signer
    locktime: u64, 
    locktime_blind: scalar::Scalar,
}

fn generate_fake_tx() -> Transaction {
    let bp_gens = BulletproofGens::new(64, 1);
    let pc_gens = PedersenGens::default();
    let secret_value = 1037578891u64;
    let mut prover_transcript = Transcript::new(b"locktime example");
    let (proof, _) = RangeProof::prove_single(
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
        pseudo_locktime_commitment: empty_point(),
        locktime_range_proof: proof,
        locktime_aux: 0,
    };
    // normally returns proof and committed_value as a compressed Ristretto point, but we don't
    // need the commitment
    let (proof, _) = RangeProof::prove_single(
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
        amount_range_proof: proof,
    };

    Transaction {
        locktime: locktime,
        locktime_blind: locktime_blind,
        locktime_commitment: u64_to_scalar(locktime) * H() + locktime_blind * G,
        inputs: vec![input],
        outputs: vec![output],
        transaction_time: 0u64,
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
    let mut input_amount_pseudo_ring: [ristretto::RistrettoPoint; RINGSIZE] = [empty_point(); RINGSIZE];
    for i in 0..RINGSIZE {
        input_amount_pseudo_ring[i] = input_amount_ring[i] - input_amount_pseudo_commitment;
    }

    // generate locktime pseudo commitment and ring as will be used in the signature and
    // transaction input
    let input_locktime_pseudo_blind = random_scalar();
    let input_locktime_pseudo_commitment = input_locktime * H() + input_locktime_pseudo_blind * G;
    let mut input_locktime_pseudo_ring: [ristretto::RistrettoPoint; RINGSIZE] = [empty_point(); RINGSIZE];
    for i in 0..RINGSIZE {
        input_locktime_pseudo_ring[i] = input_locktime_ring[i] - input_locktime_pseudo_commitment;
    }

    // choose an auxiliary locktime that will be communicated in plaintext
    let input_locktime_aux = u64_to_scalar(16u64);
    // generate 64bit range proof for locktime commitment
    let bp_gens = BulletproofGens::new(64, 1);
    let pc_gens = PedersenGens {B: H(), B_blinding: G};
    // prove that the auxiliary locktime is lower than the input_locktime
    let secret_value = scalar_to_u64(input_locktime_aux) - scalar_to_u64(input_locktime);
    let mut prover_transcript = Transcript::new(b"locktime example");
    let input_locktime_pseudo_blind_negative = u64_to_scalar(0u64) - input_locktime_pseudo_blind;
    let (locktime_range_proof, _) = RangeProof::prove_single(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        secret_value,
        &input_locktime_pseudo_blind_negative,
        32,
    )
    .expect("I promise this will totally never fail");

    // generate CLSAG signature
    let signature: Signature = clsag_sign(
        privkey_index,
        message,
        privkey,
        public_ring,
        input_amount_blind - input_amount_pseudo_blind,
        input_amount_pseudo_ring,
        input_locktime_blind - input_locktime_pseudo_blind,
        input_locktime_pseudo_ring,
    );

    let input = Input {
        ring_member_offsets: ring_member_offsets,
        signature: signature,
        pseudo_amount_commitment: input_amount_pseudo_commitment,
        pseudo_locktime_commitment: input_locktime_pseudo_commitment,
        locktime_range_proof: locktime_range_proof,
        locktime_aux: scalar_to_u64(input_locktime_aux),
    };

    // output amount commitment
    let output_amount = input_amount;
    let output_amount_blind = input_amount_pseudo_blind;
    let output_amount_commitment = input_amount * H() + output_amount_blind * G;
    let (output_amount_range_proof, output_amount_committed_value) = RangeProof::prove_single(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        scalar_to_u64(output_amount),
        &output_amount_blind,
        32,
    )
    .expect("I promise this will totally never fail");
    assert_eq!(output_amount_commitment.compress(), output_amount_committed_value);
    
    let privkey = random_scalar();
    let output = Output {
        one_time_pubkey: privkey * G,
        one_time_privkey: privkey,
        amount_commitment: output_amount * H() + output_amount_blind * G,
        amount: scalar_to_u64(output_amount),
        amount_blind: output_amount_blind,
        amount_range_proof: output_amount_range_proof,
    };

    let tx_locktime = 10u64;
    let tx_locktime_blind = random_scalar();

    let tx = Transaction {
        locktime: tx_locktime,
        locktime_blind: tx_locktime_blind,
        locktime_commitment: u64_to_scalar(tx_locktime) * H() + tx_locktime_blind * G,
        inputs: vec![input],
        outputs: vec![output],
        transaction_time: 0u64,
    };

    // now verify the transaction with just the public information available
    
    /* verify inputs */

    let mut verify_public_ring: [ristretto::RistrettoPoint; RINGSIZE] = [empty_point(); RINGSIZE];
    let mut verify_input_amount_ring: [ristretto::RistrettoPoint; RINGSIZE] = [empty_point(); RINGSIZE];
    let mut verify_input_locktime_ring: [ristretto::RistrettoPoint; RINGSIZE] = [empty_point(); RINGSIZE];
    let mut k = 0;

    for index in tx.inputs[0].ring_member_offsets.iter() {
        let i = *index as usize;
        let transaction = &fake_txs[i];
        verify_public_ring[k] = transaction.outputs[0].one_time_pubkey;
        verify_input_amount_ring[k] = transaction.outputs[0].amount_commitment - tx.inputs[0].pseudo_amount_commitment;
        verify_input_locktime_ring[k] = transaction.locktime_commitment - tx.inputs[0].pseudo_locktime_commitment;
        k += 1;
    }

    clsag_verify(
        message,
        verify_public_ring, // as collected from ring_member_offsets
        verify_input_amount_ring, // as collected from ring_member_offsets - input_amount_pseudo_commitment
        verify_input_locktime_ring, // as collected from ring_member_offsets - input_locktime_pseudo_commitment
        &tx.inputs[0].signature,
    );

    let mut verifier_transcript = Transcript::new(b"locktime example");
    let locktime_proof_commitment = (u64_to_scalar(tx.inputs[0].locktime_aux) * H() - tx.inputs[0].pseudo_locktime_commitment).compress();
    assert!(
        tx.inputs[0].locktime_range_proof
            .verify_single(&bp_gens, &pc_gens, &mut verifier_transcript, &locktime_proof_commitment, 32)
            .is_ok()
    );

    // verify that the chosen is auxiliary time is younger than the transaction time
    assert!( tx.transaction_time < tx.inputs[0].locktime_aux);

    /* verify outputs */

    let amount_proof_commitment = tx.outputs[0].amount_commitment.compress();
    assert!(
        tx.outputs[0].amount_range_proof
            .verify_single(&bp_gens, &pc_gens, &mut verifier_transcript, &amount_proof_commitment, 32)
            .is_ok()
    );
    
    // verify that the amounts actually equal zero
    assert_eq!((tx.inputs[0].pseudo_amount_commitment - tx.outputs[0].amount_commitment).compress().as_bytes(), &[0u8; 32]);
}
