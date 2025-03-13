use ark_ed_on_bn254::{EdwardsProjective as Point, Fq as Scalar};
use ark_ff::{BigInteger, One, PrimeField, UniformRand, Zero};
use ark_ec::{CurveGroup, PrimeGroup};

#[derive(Debug)]
pub enum CryptoError {
    InvalidInputSize,
    InvalidPublicKey,
    InvalidCiphertext,
    DecryptionFailed,
}



#[derive(Debug, Clone)]
pub struct BabyJubPoint {
    x: Scalar,
    y: Scalar,
}

#[derive(Debug, Clone)]
pub struct Message {
    point: BabyJubPoint,
    x_increment: Scalar,
}

#[derive(Debug, Clone)]
pub struct ElGamalCiphertext {
    c1: BabyJubPoint,
    c2: BabyJubPoint,
    x_increment: Scalar,
}

pub fn gen_pub_key(priv_key: Scalar) -> Point {
    Point::generator().mul_bigint(priv_key.into_bigint())
}



pub fn generate_random_scalar() -> Scalar {
    let mut rng = ark_std::test_rng();
    Scalar::rand(&mut rng)
}

pub fn encode_to_message(original: Scalar) -> Message {
    let mut rng = ark_std::test_rng();
    let random_point = Point::rand(&mut rng);
    
    let x_increment = random_point.into_affine().x - original;
    assert!(x_increment >= Scalar::zero());
    
    let affine_point = random_point.into_affine();
    let point = BabyJubPoint { x: affine_point.x, y: affine_point.y };
    
    Message { point, x_increment }
}

pub fn decode_message(message: &Message) -> Scalar {
    let decoded = message.point.x - message.x_increment;
    assert!(decoded >= Scalar::zero());
    
    decoded
}

pub fn encrypt(plaintext: Scalar, pub_key: Point, random_val: Scalar) -> ElGamalCiphertext {
    let message = encode_to_message(plaintext);
    
    let c1_point = Point::generator().mul_bigint(random_val.into_bigint());
    let pky = pub_key.mul_bigint(random_val.into_bigint());
    let message_point = Point::new(message.point.x, message.point.y, Scalar::one(), Scalar::one());
    let c2_point = message_point + pky;
    
    let c1_affine = c1_point.into_affine();
    let c2_affine = c2_point.into_affine();
    
    ElGamalCiphertext {
        c1: BabyJubPoint { x: c1_affine.x, y: c1_affine.y },
        c2: BabyJubPoint { x: c2_affine.x, y: c2_affine.y },
        x_increment: message.x_increment,
    }
}

pub fn decrypt(priv_key: Scalar, ciphertext: &ElGamalCiphertext) -> Scalar {
    let c1_point = Point::new(ciphertext.c1.x, ciphertext.c1.y, Scalar::one(), Scalar::one());

    let priv_c1 = c1_point.mul_bigint(priv_key.into_bigint());

    let c2_point = Point::new(ciphertext.c2.x, ciphertext.c2.y, Scalar::one(), Scalar::one());

    let decrypted_point = c2_point - priv_c1;

    decode_message(&Message {
        point: BabyJubPoint { x: decrypted_point.into_affine().x, y: decrypted_point.into_affine().y },
        x_increment: ciphertext.x_increment,
    })
}

pub fn rerandomize(ciphertext: &ElGamalCiphertext) -> ElGamalCiphertext {
    let random_val = generate_random_scalar();
    let c1_point = Point::generator().mul_bigint(random_val.into_bigint());
    let c2_point = Point::new(ciphertext.c2.x, ciphertext.c2.y, Scalar::one(), Scalar::one());
    
    let c1_affine = c1_point.into_affine();
    let c2_affine = c2_point.into_affine();
    
    ElGamalCiphertext {
        c1: BabyJubPoint { x: c1_affine.x, y: c1_affine.y },
        c2: BabyJubPoint { x: c2_affine.x, y: c2_affine.y },
        x_increment: ciphertext.x_increment,
    }
}



pub fn encrypt_bytes(plaintext: &[u8], pub_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if plaintext.len() > 32 {
        return Err(CryptoError::InvalidInputSize);
    }
    if pub_key.len() != 64 {
        return Err(CryptoError::InvalidPublicKey);
    }

    let pub_key_x = &pub_key[0..32];
    let pub_key_y = &pub_key[32..64];

    let pub_key = ark_ed_on_bn254::EdwardsAffine::new(
        ark_ed_on_bn254::Fq::from_be_bytes_mod_order(pub_key_x),
        ark_ed_on_bn254::Fq::from_be_bytes_mod_order(pub_key_y),
    );

    let plaintext = ark_ed_on_bn254::Fq::from_be_bytes_mod_order(plaintext);
    let random_val = generate_random_scalar();
    let ciphertext = encrypt(plaintext, pub_key.into(), random_val);

    let mut result = Vec::new();
    result.extend_from_slice(&ciphertext.c1.x.into_bigint().to_bytes_be());
    result.extend_from_slice(&ciphertext.c1.y.into_bigint().to_bytes_be());
    result.extend_from_slice(&ciphertext.c2.x.into_bigint().to_bytes_be());
    result.extend_from_slice(&ciphertext.c2.y.into_bigint().to_bytes_be());
    result.extend_from_slice(&ciphertext.x_increment.into_bigint().to_bytes_be());

    Ok(result)
}


pub fn decrypt_bytes(priv_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.len() != 160 {
        return Err(CryptoError::InvalidCiphertext);
    }

    let priv_key = ark_ff::Fp::from_be_bytes_mod_order(priv_key);

    let c1_x = &ciphertext[0..32];
    let c1_y = &ciphertext[32..64];
    let c2_x = &ciphertext[64..96];
    let c2_y = &ciphertext[96..128];
    let x_increment = &ciphertext[128..160];

    let c1 = BabyJubPoint {
        x: ark_ed_on_bn254::Fq::from_be_bytes_mod_order(c1_x),
        y: ark_ed_on_bn254::Fq::from_be_bytes_mod_order(c1_y),
    };
    let c2 = BabyJubPoint {
        x: ark_ed_on_bn254::Fq::from_be_bytes_mod_order(c2_x),
        y: ark_ed_on_bn254::Fq::from_be_bytes_mod_order(c2_y),
    };
    let x_increment = ark_ed_on_bn254::Fq::from_be_bytes_mod_order(x_increment);

    let ciphertext = ElGamalCiphertext { c1, c2, x_increment };

    let decrypted = decrypt(priv_key, &ciphertext);

    if decrypted.is_zero() {
        return Err(CryptoError::DecryptionFailed);
    }

    let mut result = Vec::new();
    result.extend_from_slice(&decrypted.into_bigint().to_bytes_be());

    Ok(result)
}


