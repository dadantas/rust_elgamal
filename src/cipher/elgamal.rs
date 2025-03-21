use ark_ec::{twisted_edwards::TECurveConfig, AffineRepr, CurveGroup, PrimeGroup};
use ark_ed_on_bn254::{EdwardsProjective as Point, Fq as Scalar, EdwardsAffine};
use ark_ff::{BigInteger, Field, One, PrimeField, UniformRand};
use ark_std::rand::SeedableRng as _;

#[derive(Debug)]
pub enum CryptoError {
    InvalidInputSize,
    InvalidPublicKey,
    InvalidCiphertext,
}


#[derive(Debug, Clone)]
pub struct ElGamalCiphertext {
    c1: ark_ed_on_bn254::EdwardsAffine,
    c2: ark_ed_on_bn254::EdwardsAffine,
}


pub fn gen_pub_key(priv_key: Scalar) -> Point {
    Point::generator().mul_bigint(priv_key.into_bigint())
}

pub fn pub_key_to_bytes(pub_key: Point) -> Vec<u8> {
    let pub_key_affine = pub_key.into_affine();
    let mut result = Vec::new();
    result.extend_from_slice(&pub_key_affine.x.into_bigint().to_bytes_le());
    result.extend_from_slice(&pub_key_affine.y.into_bigint().to_bytes_le());
    result
}

pub fn gen_pub_key_bytes(priv_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if priv_key.len() != 32 {
        return Err(CryptoError::InvalidPublicKey);
    }

    let priv_key = Scalar::from_le_bytes_mod_order(priv_key);
    let pub_key = gen_pub_key(priv_key);

    Ok(pub_key_to_bytes(pub_key))
}

pub fn gen_priv_key_bytes() -> Vec<u8> {
    let priv_key = generate_random_scalar();
    priv_key.into_bigint().to_bytes_le()
}

pub fn generate_random_scalar() -> Scalar {
    let mut rng = ark_std::rand::rngs::StdRng::from_seed(rand::Rng::random(&mut rand::rng()));
    Scalar::rand(&mut rng)
}

pub fn get_y_from_x(x: Scalar) -> Option<Scalar> {
    let coeff_d: Scalar = ark_ed_on_bn254::EdwardsConfig::COEFF_D.into_bigint().into();
    let one_minus_x2 = Scalar::one() - x.square();

    let denom = Scalar::one() - (coeff_d * x.square());
    let denom_inv = denom.inverse()?;

    let y2 = one_minus_x2 * denom_inv;

    y2.sqrt()
}


//Probabilistic encoding, unfortunately this is the only way i found that works messages must be < 32 bytes
pub fn encode_to_message(original: &[u8]) -> EdwardsAffine {
    let mut rng = ark_std::rand::rngs::StdRng::from_seed(rand::Rng::random(&mut rand::rng()));

    loop {
        let random_point = Point::rand(&mut rng);

        // Store length of message in lower 8 bits of x
        let mut x: Vec<u8> = random_point.into_affine().x.into_bigint().to_bytes_le();
        x[0] = original.len() as u8;
        // Copy message into x using slice copy 
        x[1..original.len() + 1].copy_from_slice(original);
        // Check if valid
        let x = Scalar::from_le_bytes_mod_order(&x);
        let new_y = get_y_from_x(x);
        match new_y {
            Some(y) => {
                let new_point = Point::new_unchecked(x, y, Scalar::one(), Scalar::one()).into_affine().mul_by_cofactor();
                // **Force the point into the correct subgroup**

                if new_point.is_on_curve()
                    && new_point.is_in_correct_subgroup_assuming_on_curve() && new_point.mul_by_cofactor_inv().x == x
                {
                    return new_point
                }
            }
            None => {
                continue;
            }
        }
    }
}


pub fn decode_message(message: &EdwardsAffine) -> Vec<u8> {
    //print type of x
    let p_red = Point::new(message.x, message.y, Scalar::one(), Scalar::one()).into_affine().mul_by_cofactor_inv();
    let x = p_red.x.into_bigint().to_bytes_le();
    let len = x[0] as usize;
    x[1..len + 1].to_vec()
}

pub fn encrypt(plaintext: &[u8], pub_key: Point, random_val: Scalar) -> Result<ElGamalCiphertext, CryptoError> {
    if plaintext.len() > 31 {
        return Err(CryptoError::InvalidInputSize);
    }

    let message = encode_to_message(plaintext);
    let c1_point = Point::generator().mul_bigint(random_val.into_bigint());

    let pky = pub_key.mul_bigint(random_val.into_bigint());
    let message_point = Point::new(message.x, message.y, Scalar::one(), Scalar::one());

    let c2_point = message_point + pky;

    let c1_affine = c1_point.into_affine();
    let c2_affine = c2_point.into_affine();

    Ok(ElGamalCiphertext {
        c1: c1_affine,
        c2: c2_affine,
    })
}

pub fn decrypt(priv_key: Scalar, ciphertext: &ElGamalCiphertext) -> Vec<u8> {
    let c1_point = Point::new(
        ciphertext.c1.x,
        ciphertext.c1.y,
        Scalar::one(),
        Scalar::one(),
    );

    let priv_c1 = c1_point.mul_bigint(priv_key.into_bigint());

    let c2_point = Point::new(
        ciphertext.c2.x,
        ciphertext.c2.y,
        Scalar::one(),
        Scalar::one(),
    );

    let decrypted_point = c2_point - priv_c1;

    decode_message(&decrypted_point.into_affine())
}

pub fn rerandomize(ciphertext: &ElGamalCiphertext, pubkey: Point) -> ElGamalCiphertext {
    let random_val = generate_random_scalar();
    let c1_point = Point::generator().mul_bigint(random_val.into_bigint()) + Point::new(ciphertext.c1.x, ciphertext.c1.y, Scalar::one(), Scalar::one());
    let c2_point = ciphertext.c2 + pubkey.mul_bigint(random_val.into_bigint());

    let c1_affine = c1_point.into_affine();
    let c2_affine = c2_point.into_affine();

    ElGamalCiphertext {
        c1: c1_affine,
        c2: c2_affine,
    }
}

pub fn encrypt_bytes(plaintext: &[u8], pub_key: &[u8], random_val: Scalar) -> Result<Vec<u8>, CryptoError> {
    if plaintext.len() > 32 {
        return Err(CryptoError::InvalidInputSize);
    }
    if pub_key.len() != 64 {
        return Err(CryptoError::InvalidPublicKey);
    }

    let pub_key_x = &pub_key[0..32];
    let pub_key_y = &pub_key[32..64];

    let pub_key = ark_ed_on_bn254::EdwardsAffine::new(
        ark_ed_on_bn254::Fq::from_le_bytes_mod_order(pub_key_x),
        ark_ed_on_bn254::Fq::from_le_bytes_mod_order(pub_key_y),
    );

    let ciphertext = encrypt(plaintext, pub_key.into(), random_val);
    match ciphertext {
        Err(e) => Err(e),
        Ok(ciphertext) => {
            let mut result = Vec::new();
            result.extend_from_slice(&ciphertext.c1.x.into_bigint().to_bytes_le());
            result.extend_from_slice(&ciphertext.c1.y.into_bigint().to_bytes_le());
            result.extend_from_slice(&ciphertext.c2.x.into_bigint().to_bytes_le());
            result.extend_from_slice(&ciphertext.c2.y.into_bigint().to_bytes_le());

            Ok(result)
        }
    }
}

pub fn decrypt_bytes(priv_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.len() != 128 {
        return Err(CryptoError::InvalidCiphertext);
    }

    let priv_key = ark_ff::Fp::from_le_bytes_mod_order(priv_key);

    let c1_x = &ciphertext[0..32];
    let c1_y = &ciphertext[32..64];
    let c2_x = &ciphertext[64..96];
    let c2_y = &ciphertext[96..128];

    let c1 = EdwardsAffine {
        x: ark_ed_on_bn254::Fq::from_le_bytes_mod_order(c1_x),
        y: ark_ed_on_bn254::Fq::from_le_bytes_mod_order(c1_y),
    };
    let c2 = EdwardsAffine {
        x: ark_ed_on_bn254::Fq::from_le_bytes_mod_order(c2_x),
        y: ark_ed_on_bn254::Fq::from_le_bytes_mod_order(c2_y),
    };

    let ciphertext = ElGamalCiphertext { c1, c2 };

    let decrypted = decrypt(priv_key, &ciphertext);

    Ok(decrypted)
}

pub fn rerandomize_bytes(ciphertext: &[u8], pub_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.len() != 128 {
        return Err(CryptoError::InvalidCiphertext);
    }
    if pub_key.len() != 64 {
        return Err(CryptoError::InvalidPublicKey);
    }

    let pub_key_x = &pub_key[0..32];
    let pub_key_y = &pub_key[32..64];

    let pub_key = ark_ed_on_bn254::EdwardsAffine::new(
        ark_ed_on_bn254::Fq::from_le_bytes_mod_order(pub_key_x),
        ark_ed_on_bn254::Fq::from_le_bytes_mod_order(pub_key_y),
    );

    let c1_x = &ciphertext[0..32];
    let c1_y = &ciphertext[32..64];
    let c2_x = &ciphertext[64..96];
    let c2_y = &ciphertext[96..128];

    let c1 = EdwardsAffine {
        x: ark_ed_on_bn254::Fq::from_le_bytes_mod_order(c1_x),
        y: ark_ed_on_bn254::Fq::from_le_bytes_mod_order(c1_y),
    };
    let c2 = EdwardsAffine {
        x: ark_ed_on_bn254::Fq::from_le_bytes_mod_order(c2_x),
        y: ark_ed_on_bn254::Fq::from_le_bytes_mod_order(c2_y),
    };

    let ciphertext = ElGamalCiphertext { c1, c2 };

    let rerandomized = rerandomize(&ciphertext, pub_key.into());

    let mut result = Vec::new();
    result.extend_from_slice(&rerandomized.c1.x.into_bigint().to_bytes_le());
    result.extend_from_slice(&rerandomized.c1.y.into_bigint().to_bytes_le());
    result.extend_from_slice(&rerandomized.c2.x.into_bigint().to_bytes_le());
    result.extend_from_slice(&rerandomized.c2.y.into_bigint().to_bytes_le());

    Ok(result)
}
