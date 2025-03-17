
use std::time::Instant;


use openssl::symm::Cipher;
use hex::encode;
use rust_elgamal::{decrypt_message, encrypt_message, free_buffer, free_keypair, generate_keypair, rerandomize_ciphertext};

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


    let keypair = generate_keypair();
    let keypair_ref = unsafe { &*keypair };

    let message = "Hello, world!";
    start = Instant::now();
    let mut ciphertext = encrypt_message(keypair_ref.pub_key.as_ptr(), message.as_ptr(), message.len());
    println!("ElGamal Enc Time: {:?}", start.elapsed());

    ciphertext = rerandomize_ciphertext(ciphertext, keypair_ref.pub_key.as_ptr());
    let mut size = 0;
    let decrypted_message = decrypt_message(keypair_ref.priv_key.as_ptr(), ciphertext, &mut size);



    let decrypted_message_slice = unsafe { std::slice::from_raw_parts(decrypted_message, size) };

    println!("Decrypted: {:?}", String::from_utf8(decrypted_message_slice.to_vec()).unwrap());

    free_keypair(keypair);
    free_buffer(ciphertext);
    free_buffer(decrypted_message);

}