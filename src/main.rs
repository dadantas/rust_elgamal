
use std::{str::FromStr, time::Instant};


use ark_ec::CurveGroup;
use ark_ff::{BigInt, BigInteger, PrimeField};
use openssl::symm::Cipher;
use hex::encode;
use rust_elgamal::elgamal::*;

fn main() {
    //aes ctr
    let plain = "Hello, world!";
    let key = "0123456789abcdef";
    let iv = "0123456789abcdef";
    let cipher = Cipher::aes_128_ctr();
    let mut start = Instant::now();
    let encrypted = openssl::symm::encrypt(cipher, key.as_bytes(), Some(iv.as_bytes()), plain.as_bytes()).unwrap();
    println!("AES/CTR Enc Time: {:?}", start.elapsed());
    start = Instant::now();
    let decrypted = openssl::symm::decrypt(cipher, key.as_bytes(), Some(iv.as_bytes()), &encrypted).unwrap();
    println!("AES/CTR Dec Time: {:?}", start.elapsed());
    println!("Encrypted: {}", encode(&encrypted));
    println!("Decrypted: {}", String::from_utf8(decrypted).unwrap());

    //test encode and decode
    let original = generate_random_scalar();
    let message = encode_to_message(original);
    let decoded = decode_message(&message);
    println!("Original: {:?}", original);
    println!("Decoded: {:?}", decoded);



    let plain = generate_random_scalar();
    let priv_key = generate_random_scalar();
    let pub_key = gen_pub_key(priv_key);
    let random_val = generate_random_scalar();

    println!("Plain: {:?}", plain);
    start = Instant::now();
    let ciphertext = encrypt(plain, pub_key, random_val);
    println!("ElGamal Enc Time: {:?}", start.elapsed());

    start = Instant::now();
    let decrypted = decrypt(priv_key, &ciphertext);
    println!("Decrypted: {:?}", decrypted);
    println!("ElGamal Dec Time: {:?}", start.elapsed());

    let rerandomized = rerandomize(&ciphertext);
    let decrypted_rerandomized = decrypt(priv_key, &rerandomized);
    println!("Decrypted rerandomized: {:?}", decrypted_rerandomized);




    // let priv_key = generate_random_scalar();
    let mut pub_key_bytes = Vec::new();
    pub_key_bytes.extend_from_slice(&pub_key.into_affine().x.into_bigint().to_bytes_be());
    pub_key_bytes.extend_from_slice(&pub_key.into_affine().y.into_bigint().to_bytes_be());

    println!("pub_key: {:?}", pub_key.into_affine());
    println!("pub_key_bytes: {:?}", pub_key_bytes);
    println!("Length: {:?}", pub_key_bytes.len());

    let plain = "Hello";
    //pad plain 

    let cipher = encrypt_bytes(&plain.as_bytes(), &pub_key_bytes);
    match cipher {
        Ok(cipher) => {
            println!("Encrypted: {:?}", cipher);
            let decrypted = decrypt_bytes(&priv_key.into_bigint().to_bytes_be(), &cipher);
            println!("Decrypted: {:?}", decrypted);
            match decrypted {
                Ok(decrypted_bytes) => {
                    //trim
                    let mut decrypted_bytes = decrypted_bytes;
                    decrypted_bytes.retain(|&x| x != 0);
                    
                    println!("Decrypted: {:?}", String::from_utf8(decrypted_bytes).unwrap());
                }
                Err(e) => {
                    println!("Decryption error: {:?}", e);
                }
            }
        }
        Err(e) => {
            println!("Error: {:?}", e);
        }
        
    }

}
