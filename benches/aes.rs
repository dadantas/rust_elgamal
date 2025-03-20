use criterion::{criterion_group, criterion_main, Criterion};
use aes::Aes128;
use aes::cipher::{ BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray,
};


//benchmarks for aes ctr

fn bench_encrypt(c: &mut Criterion) {
    let key = GenericArray::from([0u8; 16]);
    let mut block = GenericArray::from([42u8; 16]);
    
    // Initialize cipher
    let cipher = Aes128::new(&key);
    c.bench_function("AES/CTR Encryption", |b| {
        b.iter(|| {
            cipher.encrypt_block(&mut block);
        })
    });
}


fn bench_decrypt(c: &mut Criterion) {
    let key = GenericArray::from([0u8; 16]);
    let mut block = GenericArray::from([42u8; 16]);
    
    // Initialize cipher
    let cipher = Aes128::new(&key);
    cipher.encrypt_block(&mut block);
    c.bench_function("AES/CTR Decryption", |b| {
        b.iter(|| {
            cipher.decrypt_block(&mut block);
        })
    });
}


//benchmarks for elgamal
criterion_group!(benches, bench_encrypt, bench_decrypt);
criterion_main!(benches);
