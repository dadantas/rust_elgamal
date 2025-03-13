use criterion::{criterion_group, criterion_main, Criterion};
use ark_ed_on_bn254::EdwardsProjective as Point;
use ark_ec::PrimeGroup;
use ark_ff::PrimeField;
use rust_elgamal::elgamal::*;  // Ensure this is correctly imported

fn bench_encrypt(c: &mut Criterion) {
    let priv_key = generate_random_scalar();
    let pub_key = Point::generator().mul_bigint(priv_key.into_bigint());

    c.bench_function("ElGamal Encryption", |b| {
        b.iter(|| {
            let plaintext = generate_random_scalar();
            let random_val = generate_random_scalar();
            encrypt(plaintext, pub_key, random_val)
        })
    });
}

fn bench_decrypt(c: &mut Criterion) {
    let priv_key = generate_random_scalar();
    let pub_key = Point::generator().mul_bigint(priv_key.into_bigint());

    let plaintext = generate_random_scalar();
    let random_val = generate_random_scalar();
    let ciphertext = encrypt(plaintext, pub_key, random_val);

    c.bench_function("ElGamal Decryption", |b| {
        b.iter(|| decrypt(priv_key, &ciphertext))
    });
}

// Register the benchmark functions
criterion_group!(benches, bench_encrypt, bench_decrypt);
criterion_main!(benches);
