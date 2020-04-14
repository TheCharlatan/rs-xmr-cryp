#![allow(non_snake_case)]

extern crate rand_core;
use rand_core::{OsRng, RngCore};

extern crate curve25519_dalek;
extern crate ed25519_dalek;
use curve25519_dalek::constants;
use curve25519_dalek::ristretto;
use curve25519_dalek::scalar;

extern crate sha3;
use sha3::{Keccak512};

/*
* some utility functions and constants for EC crypto ops
*/

pub const RINGSIZE: usize = 10;
pub const G: ristretto::RistrettoPoint = constants::RISTRETTO_BASEPOINT_POINT;

pub fn ristretto_point_hash(point: ristretto::RistrettoPoint) -> ristretto::RistrettoPoint {
    let point_bytes: [u8; 32] = point.compress().to_bytes();
    let hash_point = ristretto::RistrettoPoint::hash_from_bytes::<Keccak512>(&point_bytes);
    hash_point
}

pub fn random_scalar() -> scalar::Scalar {
    return scalar::Scalar::from_bytes_mod_order_wide(&[OsRng.next_u64() as u8; 64]);
}

pub fn random_point() -> ristretto::RistrettoPoint {
    return ristretto::RistrettoPoint::from_uniform_bytes(&[OsRng.next_u64() as u8; 64]);
}

pub fn empty_scalar() -> scalar::Scalar {
    return scalar::Scalar::from_bytes_mod_order([0u8; 32]);
}

pub fn empty_point() -> ristretto::RistrettoPoint {
    return ristretto::RistrettoPoint::from_uniform_bytes(&[0u8; 64]);
}

pub fn H() -> ristretto::RistrettoPoint {
    return ristretto_point_hash(G);
}

pub fn u64_to_32_bytes_u8_array(number: u64) -> [u8; 32] {
    let bytes = number.to_le_bytes();
    let mut data = [0u8; 32];
    for i in 0..32 {
        if i < 8 {
            data[i] = bytes[i];
        }
    }
    data
}

pub fn u64_to_scalar(number: u64) -> scalar::Scalar {
    return scalar::Scalar::from_bytes_mod_order(u64_to_32_bytes_u8_array(number));
}

pub fn bytes_u8_array_to_u64(data: [u8; 32]) -> u64 {
    let mut bytes = [0u8;8];
    for i in 0..8 {
        bytes[i] = data[i];
    }
    u64::from_le_bytes(bytes)
}

pub fn scalar_to_u64(scalar_element: scalar::Scalar) -> u64 {
    return bytes_u8_array_to_u64(scalar_element.to_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_byte_conversion() {
        let number: u64 = 18345678999999999999u64;
        let data: [u8; 32] = u64_to_32_bytes_u8_array(number);
        assert_eq!(number, bytes_u8_array_to_u64(data));
    }

    #[test]
    fn test_u64_to_scalar_conversion() {
        let number: u64 = 185404040293423;
        let scalar = scalar::Scalar::from_bytes_mod_order(u64_to_32_bytes_u8_array(number));
        assert_eq!(number, bytes_u8_array_to_u64(scalar.to_bytes()));
    }

    #[test]
    fn test_scalar_convertion() {
        let number: u64 = 18345678999999999999u64;
        assert_eq!(number, scalar_to_u64(u64_to_scalar(number)));
    }
}

