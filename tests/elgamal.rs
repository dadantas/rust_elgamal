use rust_elgamal::{decrypt_message, encrypt_message, free_keypair, free_buffer, generate_keypair, rerandomize_ciphertext};


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

    let message = [1u8; 32];
    let ciphertext = encrypt_message(keypair_ref.pub_key.as_ptr(), message.as_ptr());
    assert!(!ciphertext.is_null());
    //check size of ciphertext
    let ciphertext_slice = unsafe { std::slice::from_raw_parts(ciphertext, 160) };
    assert_eq!(ciphertext_slice.len(), 160);


    let decrypted_message = decrypt_message(keypair_ref.priv_key.as_ptr(), ciphertext);
    assert!(!decrypted_message.is_null());

    let decrypted_message_slice = unsafe { std::slice::from_raw_parts(decrypted_message, 32) };
    assert_eq!(message, decrypted_message_slice);

    unsafe {
        free_keypair(keypair);
        free_buffer(ciphertext);
        free_buffer(decrypted_message);
    }
}

#[test]
fn test_rerandomization() {
    let keypair = generate_keypair();
    let keypair_ref = unsafe { &*keypair };

    let message = [1u8; 32];
    let ciphertext = encrypt_message(keypair_ref.pub_key.as_ptr(), message.as_ptr());
    assert!(!ciphertext.is_null());

    let rerandomized_ciphertext = rerandomize_ciphertext(ciphertext);
    assert!(!rerandomized_ciphertext.is_null());

    let decrypted_message = decrypt_message(keypair_ref.priv_key.as_ptr(), rerandomized_ciphertext);
    assert!(!decrypted_message.is_null());

    let decrypted_message_slice = unsafe { std::slice::from_raw_parts(decrypted_message, 32) };
    assert_eq!(message, decrypted_message_slice);

    unsafe {
        free_keypair(keypair);
        free_buffer(ciphertext);
        free_buffer(rerandomized_ciphertext);
    }
}
