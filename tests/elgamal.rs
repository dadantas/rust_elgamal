use rust_elgamal::{decrypt_message, encrypt_message, free_buffer, free_keypair, gen_random_scalar, generate_keypair, rerandomize_ciphertext};


#[test]
fn test_keypair_generation() {
    let keypair = generate_keypair();
    assert!(!keypair.is_null());

    let keypair_ref = unsafe { &*keypair };
    assert!(keypair_ref.priv_key != [0u8; 32]);
    assert!(keypair_ref.pub_key != [0u8; 64]);

    free_keypair(keypair);
}

#[test]
fn test_encryption_decryption() {
    let keypair = generate_keypair();
    let keypair_ref = unsafe { &*keypair };

    let message = "Hello, world!";
    let random_val = gen_random_scalar();
    let ciphertext = encrypt_message(keypair_ref.pub_key.as_ptr(), random_val, message.as_ptr(), message.len());
    assert!(!ciphertext.is_null());
    //check size of ciphertext
    let ciphertext_slice = unsafe { std::slice::from_raw_parts(ciphertext, 128) };
    assert_eq!(ciphertext_slice.len(), 128);

    let mut size = 0;
    let decrypted_message = decrypt_message(keypair_ref.priv_key.as_ptr(), ciphertext, &mut size);
    assert!(!decrypted_message.is_null());

    let decrypted_message_slice = unsafe { std::slice::from_raw_parts(decrypted_message, size) };
    assert_eq!(message.as_bytes(), decrypted_message_slice);

    free_keypair(keypair);
    free_buffer(ciphertext);
    free_buffer(random_val as *mut u8);
    free_buffer(decrypted_message);
}

#[test]
fn test_rerandomization() {
    let keypair = generate_keypair();
    let keypair_ref = unsafe { &*keypair };

    let message = "Hello, world!";
    let random_val = gen_random_scalar();
    let ciphertext = encrypt_message(keypair_ref.pub_key.as_ptr(), random_val, message.as_ptr(), message.len());
    assert!(!ciphertext.is_null());

    let random_val2 = gen_random_scalar();
    let rerandomized_ciphertext = rerandomize_ciphertext(ciphertext, keypair_ref.pub_key.as_ptr(), random_val2);
    assert!(!rerandomized_ciphertext.is_null());

    let mut msg_len: usize = 0;
    let decrypted_message = decrypt_message(keypair_ref.priv_key.as_ptr(), rerandomized_ciphertext, &mut msg_len);
    assert!(!decrypted_message.is_null());

    let decrypted_message_slice = unsafe { std::slice::from_raw_parts(decrypted_message, msg_len) };
    assert_eq!(message.as_bytes(), decrypted_message_slice);

    free_keypair(keypair);
    free_buffer(ciphertext);
    free_buffer(random_val as *mut u8);
    free_buffer(rerandomized_ciphertext);
}
