
use std::time::Instant;


use rust_elgamal::{decrypt_message, encode_to_point, encrypt_message, free_buffer, free_keypair, gen_random_scalar, generate_keypair, rerandomize_ciphertext};

fn main() {

    let keypair = generate_keypair();
    let keypair_ref = unsafe { &*keypair };

    let message = "Hello, world!";
    let start = Instant::now();
    let random_val = gen_random_scalar();

    let encoded_point = encode_to_point(message.as_ptr(), message.len());
    let mut ciphertext = encrypt_message(keypair_ref.pub_key.as_ptr(), random_val, encoded_point);

    //free the random scalar
    free_buffer(random_val as *mut u8);
    println!("ElGamal Enc Time: {:?}", start.elapsed());


    let random_val2 = gen_random_scalar();
    ciphertext = rerandomize_ciphertext(ciphertext, keypair_ref.pub_key.as_ptr(), random_val2);
    free_buffer(random_val2 as *mut u8);
    let mut size = 0;
    let decrypted_message = decrypt_message(keypair_ref.priv_key.as_ptr(), ciphertext, &mut size);



    let decrypted_message_slice = unsafe { std::slice::from_raw_parts(decrypted_message, size) };

    println!("Decrypted: {:?}", String::from_utf8(decrypted_message_slice.to_vec()).unwrap());

    free_keypair(keypair);
    free_buffer(ciphertext);
    free_buffer(decrypted_message);
    free_buffer(encoded_point);

}