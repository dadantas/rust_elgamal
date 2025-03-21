mod cipher;

use std::str::FromStr;

use ark_ed_on_bn254::EdwardsAffine;
use ark_ff::{BigInteger, PrimeField};
use cipher::elgamal::{gen_priv_key_bytes, gen_pub_key_bytes};


#[repr(C)]
pub struct KeyPair {
    pub priv_key: [u8; 32],
    pub pub_key: [u8; 64],
}

#[unsafe(no_mangle)]
pub extern "C" fn generate_keypair() -> *mut KeyPair {
    let priv_key = gen_priv_key_bytes();
    let pub_key = gen_pub_key_bytes(&priv_key).unwrap();

    let mut priv_key_bytes = [0u8; 32];
    priv_key_bytes.copy_from_slice(&priv_key);

    let mut pub_key_bytes = [0u8; 64];
    pub_key_bytes.copy_from_slice(&pub_key);

    Box::into_raw(Box::new(KeyPair {
        priv_key: priv_key_bytes,
        pub_key: pub_key_bytes,
    }))
}


#[unsafe(no_mangle)]
pub extern "C" fn free_keypair(ptr: *mut KeyPair) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(ptr));  
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gen_random_scalar() -> *mut u8 {
    let random_scalar = cipher::elgamal::generate_random_scalar();

    let random_scalar_bytes = random_scalar.into_bigint().to_bytes_le();
    let random_scalar_bytes = random_scalar_bytes.into_boxed_slice();
    Box::into_raw(random_scalar_bytes) as *mut u8
}


#[unsafe(no_mangle)]
pub extern "C" fn encode_to_point(message: *const u8, msg_len: usize) -> *mut u8 {
    if message.is_null() {
        return std::ptr::null_mut();
    }
    let message = unsafe { std::slice::from_raw_parts(message, msg_len) };
    let point: EdwardsAffine = cipher::elgamal::encode_to_message(message);

    let mut point_bytes = Vec::new();
    point_bytes.extend_from_slice(&point.x.into_bigint().to_bytes_le());
    point_bytes.extend_from_slice(&point.y.into_bigint().to_bytes_le());


    let point_bytes = point_bytes.into_boxed_slice();
    Box::into_raw(point_bytes) as *mut u8
}



/// Encrypts a message using ElGamal encryption
/// pub_key: 64 bytes
/// random_val: a bignum in string format
/// message: arbitrary length
#[unsafe(no_mangle)]
pub extern "C" fn encrypt_message(pub_key: *const u8, random_val: *mut u8, message: *const u8, msg_len: usize) -> *mut u8 {
    if pub_key.is_null() || message.is_null() {
        return std::ptr::null_mut();
    }
    let pub_key = unsafe { std::slice::from_raw_parts(pub_key, 64) };
    let message = unsafe { std::slice::from_raw_parts(message, msg_len) };

    let random_val = unsafe {
        let random_val_bytes = std::slice::from_raw_parts(random_val, 32);
        ark_ff::Fp::from_le_bytes_mod_order(random_val_bytes)
    };
    let ciphertext = cipher::elgamal::encrypt_bytes(message, pub_key, random_val).unwrap();
    let mut ciphertext_bytes = Vec::new();
    ciphertext_bytes.extend_from_slice(&ciphertext);

    let ciphertext_bytes = ciphertext_bytes.into_boxed_slice();
    Box::into_raw(ciphertext_bytes) as *mut u8
}


#[unsafe(no_mangle)]
pub extern "C" fn decrypt_message(priv_key: *const u8, ciphertext: *const u8, plaintext_len: *mut usize) -> *mut u8 {
    let priv_key = unsafe { std::slice::from_raw_parts(priv_key, 32) };
    let ciphertext = unsafe { std::slice::from_raw_parts(ciphertext, 128) };

    let plaintext = cipher::elgamal::decrypt_bytes(priv_key, ciphertext).unwrap();

    let mut plaintext_bytes = Vec::new();
    plaintext_bytes.extend_from_slice(&plaintext);

    let plaintext_len_value = plaintext_bytes.len();
    unsafe {
        *plaintext_len = plaintext_len_value;
    }

    let plaintext_bytes = plaintext_bytes.into_boxed_slice();

    Box::into_raw(plaintext_bytes) as *mut u8
}

#[unsafe(no_mangle)]
pub extern "C" fn rerandomize_ciphertext(ciphertext: *const u8, pub_key: *const u8, random_val: *mut u8) -> *mut u8 {
    let ciphertext = unsafe { std::slice::from_raw_parts(ciphertext, 128) };
    let pub_key = unsafe { std::slice::from_raw_parts(pub_key, 64) };
    let random_val = unsafe {
        let random_val_bytes = std::slice::from_raw_parts(random_val, 32);
        ark_ff::Fp::from_le_bytes_mod_order(random_val_bytes)
    };

    let rerandomized_ciphertext = cipher::elgamal::rerandomize_bytes(ciphertext, pub_key, random_val).unwrap();

    let mut rerandomized_ciphertext_bytes = Vec::new();
    rerandomized_ciphertext_bytes.extend_from_slice(&rerandomized_ciphertext);


    let rerandomized_ciphertext_bytes = rerandomized_ciphertext_bytes.into_boxed_slice();

    Box::into_raw(rerandomized_ciphertext_bytes) as *mut u8
}


#[unsafe(no_mangle)]
pub extern "C" fn bytes_to_bignum_str(bytes: *const u8, len: usize, is_be: bool) -> *mut std::os::raw::c_char {
    let bytes = unsafe { std::slice::from_raw_parts(bytes, len) };

    let bignum = if is_be {
        ark_ed_on_bn254::Fq::from_be_bytes_mod_order(bytes)
    } else {
        ark_ed_on_bn254::Fq::from_le_bytes_mod_order(bytes)
    };

    let bignum_str = bignum.to_string();

    let c_str = std::ffi::CString::new(bignum_str).unwrap();
    c_str.into_raw()
}



#[unsafe(no_mangle)]
pub extern "C" fn free_buffer(ptr: *mut u8) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(ptr));
    }
}