use criterion::{criterion_group, criterion_main, Criterion};
use rust_elgamal::{decrypt_message, encrypt_message, free_buffer, free_keypair, generate_keypair, rerandomize_ciphertext};

fn bench_encrypt(c: &mut Criterion) {
    let keypair = generate_keypair();
    let keypair_ref = unsafe { &*keypair };

    c.bench_function("ElGamal Encryption", |b| {
        b.iter(|| {
            let message = [1u8; 32];
            let ciphertext = encrypt_message(keypair_ref.pub_key.as_ptr(), message.as_ptr());
            unsafe { drop(Box::from_raw(ciphertext)); }
        })
    });

    free_keypair(keypair);
}

fn bench_decrypt(c: &mut Criterion) {
    let keypair = generate_keypair();
    let keypair_ref = unsafe { &*keypair };

    let message = [1u8; 32];
    let ciphertext = encrypt_message(keypair_ref.pub_key.as_ptr(), message.as_ptr());

    c.bench_function("ElGamal Decryption", |b| {
        b.iter(|| {
            let decrypted_message = decrypt_message(keypair_ref.priv_key.as_ptr(), ciphertext);
            unsafe { drop(Box::from_raw(decrypted_message)); }
        })
    });

    free_keypair(keypair);
    free_buffer(ciphertext);
}

fn bench_rerandomize(c: &mut Criterion) {
    let keypair = generate_keypair();
    let keypair_ref = unsafe { &*keypair };

    let message = [1u8; 32];
    let ciphertext = encrypt_message(keypair_ref.pub_key.as_ptr(), message.as_ptr());

    c.bench_function("ElGamal Rerandomization", |b| {
        b.iter(|| {
            let rerandomized_ciphertext = rerandomize_ciphertext(ciphertext);
            unsafe { drop(Box::from_raw(rerandomized_ciphertext)); }
        })
    });

    free_keypair(keypair);
    free_buffer(ciphertext);
}


// Register the benchmark functions
criterion_group!(benches, bench_encrypt, bench_decrypt, bench_rerandomize);
criterion_main!(benches);
