extern crate rand;
extern crate ed25519_dalek;
extern crate curve25519_dalek;
extern crate sha3;

use rand::rngs::OsRng;
use ed25519_dalek::Keypair;
use ed25519_dalek::Signature;
use curve25519_dalek::edwards;
use curve25519_dalek::constants;
use curve25519_dalek::scalar;
use curve25519_dalek::ristretto;
use sha3::{Digest, Keccak256};

fn ge_fromfe_frombytes_vartime(bytes: [u8;64]) -> edwards::EdwardsPoint {
    type bignum_25519 = [i32;10];
    let u:bignum_25519 = [0,0,0,0,0,0,0,0,0];
    let v:bignum_25519 = [0,0,0,0,0,0,0,0,0];
    let w:bignum_25519 = [0,0,0,0,0,0,0,0,0];
    let x:bignum_25519 = [0,0,0,0,0,0,0,0,0];
    let y:bignum_25519 = [0,0,0,0,0,0,0,0,0];
    let z:bignum_25519 = [0,0,0,0,0,0,0,0,0];
    let sign:char;

}

fn point_hash(point: edwards::EdwardsPoint) -> edwards::EdwardsPoint {
    let point_compressed = point.compress();
    let point_bytes = point_compressed.to_bytes();
    let mut hasher = Keccak256::new();
    hasher.input(point_bytes);
    let hash_point_bytes = hasher.result();
    let hash_point_compressed = edwards::CompressedEdwardsY::from_slice(&hash_point_bytes);
    // TODO: This panics if it is none, handle properly
    let hash_point = hash_point_compressed.decompress().unwrap();
    hash_point
}

fn main() {
    let G = constants::ED25519_BASEPOINT_POINT;
    let H = point_hash(G);
        let secret: [u8; 64] = [99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 9, 9, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99];
    let secret_scalar = scalar::Scalar::from_bytes_mod_order_wide(&secret);
    let pubkey = secret_scalar * G;
    let key_image = secret_scalar; //* point_hash(pubkey);

    let mut csprng = OsRng{};
    let keypair1: Keypair = Keypair::generate(&mut csprng);

    let message: &[u8] = b"This is a test of the tsunami alert system.";
    let signature: Signature = keypair1.sign(message);

    assert!(keypair1.verify(message, &signature).is_ok());
}


