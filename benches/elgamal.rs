use criterion::{criterion_group, criterion_main, Criterion};
use rust_elgamal::{decrypt_message, encrypt_message, free_buffer, free_keypair, generate_keypair, rerandomize_ciphertext};

use rand::Rng;

const RANDOM_WORDS: [&str; 100] = [
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual", "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance", "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent", "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album", "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone", "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among", "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry", "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique", "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april", "arch", "arctic", "area", "arena", "argue", "arm", "armed", "one", "two", "three", "four", "five"];

fn bench_encrypt(c: &mut Criterion) {
    let keypair = generate_keypair();
    let keypair_ref = unsafe { &*keypair };

    c.bench_function("ElGamal Encryption", |b| {
        b.iter(|| {
            // Generate a random message of up to 30 bytes
            let mut rng = rand::rng();
            let msg = RANDOM_WORDS[rng.random_range(0..100)];
            let message_len = msg.len();
            let message: Vec<u8> = msg.bytes().collect();
            
            let ciphertext = encrypt_message(keypair_ref.pub_key.as_ptr(), message.as_ptr(), message_len);
            unsafe { drop(Box::from_raw(ciphertext)); }
        })
    });

    free_keypair(keypair);
}

fn bench_decrypt(c: &mut Criterion) {
    let keypair = generate_keypair();
    let keypair_ref = unsafe { &*keypair };

    let mut rng = rand::rng();
    let msg = RANDOM_WORDS[rng.random_range(0..100)];
    let message_len = msg.len();
    let message: Vec<u8> = msg.bytes().collect();
    
    let ciphertext = encrypt_message(keypair_ref.pub_key.as_ptr(), message.as_ptr(), message_len);

    c.bench_function("ElGamal Decryption", |b| {
        b.iter(|| {
            let mut size = 0;
            let decrypted_message = decrypt_message(keypair_ref.priv_key.as_ptr(), ciphertext, &mut size);
            unsafe { drop(Box::from_raw(decrypted_message)); }
        })
    });

    free_keypair(keypair);
    free_buffer(ciphertext);
}

fn bench_rerandomize(c: &mut Criterion) {
    let keypair = generate_keypair();
    let keypair_ref = unsafe { &*keypair };

    let mut rng = rand::rng();
    let msg = RANDOM_WORDS[rng.random_range(0..100)];
    let message_len = msg.len();
    let message: Vec<u8> = msg.bytes().collect();
    
    let ciphertext = encrypt_message(keypair_ref.pub_key.as_ptr(), message.as_ptr(), message_len);

    c.bench_function("ElGamal Rerandomization", |b| {
        b.iter(|| {
            let rerandomized_ciphertext = rerandomize_ciphertext(ciphertext, keypair_ref.pub_key.as_ptr());
            unsafe { drop(Box::from_raw(rerandomized_ciphertext)); }
        })
    });

    free_keypair(keypair);
    free_buffer(ciphertext);
}


//test encrypt with varying message sizes
fn bench_encrypt_varying_message_size(c: &mut Criterion) {
    let keypair = generate_keypair();
    let keypair_ref = unsafe { &*keypair };

    let mut group = c.benchmark_group("ElGamal Encryption Varying Message Size");
    for i in 1..=30 {
        let message: Vec<u8> = (0..i).collect();
        group.bench_with_input(format!("Message Size: {}", i), &message, |b, message| {
            b.iter(|| {
                let ciphertext = encrypt_message(keypair_ref.pub_key.as_ptr(), message.as_ptr(), message.len());
                unsafe { drop(Box::from_raw(ciphertext)); }
            })
        });
    }
    
}




// Register the benchmark functions
criterion_group!(benches, bench_encrypt, bench_decrypt, bench_rerandomize, bench_encrypt_varying_message_size);
criterion_main!(benches);
