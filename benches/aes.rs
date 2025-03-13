use criterion::{criterion_group, criterion_main, Criterion};
use openssl::symm::Cipher;


//benchmarks for aes ctr

fn bench_encrypt(c: &mut Criterion) {
    let plain = "Hello, world!";
    let key = "0123456789abcdef";
    let iv = "0123456789abcdef";
    let cipher = Cipher::aes_128_ctr();
    c.bench_function("AES/CTR Encryption", |b| {
        b.iter(|| {
            openssl::symm::encrypt(cipher, key.as_bytes(), Some(iv.as_bytes()), plain.as_bytes()).unwrap()
        })
    });
}


fn bench_decrypt(c: &mut Criterion) {
    let plain = "Hello, world!";
    let key = "0123456789abcdef";
    let iv = "0123456789abcdef";
    let cipher = Cipher::aes_128_ctr();
    let encrypted = openssl::symm::encrypt(cipher, key.as_bytes(), Some(iv.as_bytes()), plain.as_bytes()).unwrap();
    c.bench_function("AES/CTR Decryption", |b| {
        b.iter(|| {
            openssl::symm::decrypt(cipher, key.as_bytes(), Some(iv.as_bytes()), &encrypted).unwrap()
        })
    });
}


//benchmarks for elgamal
criterion_group!(benches, bench_encrypt, bench_decrypt);
criterion_main!(benches);
