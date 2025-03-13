use std::str::FromStr;

use ark_ff::{BigInt, PrimeField};
use ark_std::rand::Error;

pub mod elgamal;




// #[no_mangle]
// pub extern "C" fn encrypt(plaintext: *const u8, pub_key: *const u8) -> *const u8 {
//     let plaintext = unsafe { std::slice::from_raw_parts(plaintext, 32) };
//     let pub_key = unsafe { std::slice::from_raw_parts(pub_key, 32) };
//     let plaintext = ark_ff::Fp::from_random_bytes(&plaintext).unwrap();
//     let pub_key = ark_ff::Fp::from_random_bytes(&pub_key).unwrap();
//     let random_val = elgamal::generate_random_scalar();
//     let ciphertext = elgamal::encrypt(plaintext, pub_key, random_val);
//     let c1 = ciphertext.c1;
//     let c2 = ciphertext.c2;
//     let x_increment = ciphertext.x_increment;
//     let mut result = Vec::new();
//     result.extend_from_slice(&c1.x.to_bytes());
//     result.extend_from_slice(&c1.y.to_bytes());
//     result.extend_from_slice(&c2.x.to_bytes());
//     result.extend_from_slice(&c2.y.to_bytes());
//     result.extend_from_slice(&x_increment.to_bytes());
//     result.as_ptr()
// }