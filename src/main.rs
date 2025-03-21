
use std::time::Instant;


use rust_elgamal::{decrypt_message, encrypt_message, free_buffer, free_keypair, generate_keypair, rerandomize_ciphertext, gen_random_scalar};

fn main() {

    let keypair = generate_keypair();
    let keypair_ref = unsafe { &*keypair };

    let message = "Hello, world!";
    let start = Instant::now();
    let random_val = gen_random_scalar() as *mut std::os::raw::c_char;
    let mut ciphertext = encrypt_message(keypair_ref.pub_key.as_ptr(), random_val, message.as_ptr(), message.len());

    //free the random scalar
    free_buffer(random_val as *mut u8);
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