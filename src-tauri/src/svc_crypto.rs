use crate::result::{Error, Result};
use crypto::aead::{AeadDecryptor, AeadEncryptor};

#[derive(Debug)]
pub(crate) struct AesGcmOpts {
  raw_key: Vec<u8>,
}

impl AesGcmOpts {
  pub fn key_size() -> crypto::aes::KeySize {
    crypto::aes::KeySize::KeySize256
  }

  pub fn nonce_size() -> usize {
    12
  }

  pub fn tag_size() -> usize {
    16
  }

  pub fn salt_size() -> usize {
    8
  }

  pub fn new(key: &[u8]) -> Result<Self> {
    if key.len() < 8 {
      return Err(Error::Other("raw key must > 8 bytes".into()));
    }
    Ok(Self {
      raw_key: Vec::from(key),
    })
  }

  pub fn encrypt(&self, input: &[u8]) -> Vec<u8> {
    let salt: [u8; 8] = rand::random();
    let mut hmac256 =
      crypto::hmac::Hmac::new(crypto::sha2::Sha256::new(), self.raw_key.clone().as_slice());
    let mut pkkdf_bytes = [0; 64];
    crypto::pbkdf2::pbkdf2(&mut hmac256, &salt, 4096, &mut pkkdf_bytes[..]);
    let key = &pkkdf_bytes[..32];
    let nonce = &pkkdf_bytes[32..32 + Self::nonce_size()];
    let mut enc = crypto::aes_gcm::AesGcm::new(Self::key_size(), key, nonce, &[]);
    let mut output = Vec::from(input);
    let mut tag = [0; 16];
    enc.encrypt(input, &mut output, &mut tag);
    let mut result = Vec::from(salt);
    result.extend(output);
    result.extend(tag);
    result
  }

  pub fn decrypt(&self, input: &[u8]) -> Result<Vec<u8>> {
    if input.len() < Self::salt_size() + Self::tag_size() {
      return Err(Error::CryptoErr(format!(
        "encrypt text must > {}",
        Self::salt_size() + Self::tag_size()
      )));
    }
    let salt = &input[..8];
    let mut hmac256 =
      crypto::hmac::Hmac::new(crypto::sha2::Sha256::new(), self.raw_key.clone().as_slice());
    let mut pkkdf_bytes = [0; 64];
    crypto::pbkdf2::pbkdf2(&mut hmac256, &salt, 4096, &mut pkkdf_bytes[..]);
    let key = &pkkdf_bytes[..32];
    let nonce = &pkkdf_bytes[32..32 + Self::nonce_size()];
    let mut dec = crypto::aes_gcm::AesGcm::new(Self::key_size(), key, nonce, &[]);
    let encrypt_bytes = &input[8..(input.len() - Self::tag_size())];
    let tag = &input[(input.len() - Self::tag_size())..];
    let mut output = Vec::from(encrypt_bytes);
    if !dec.decrypt(&encrypt_bytes, &mut output, &tag) {
      return Err(Error::CryptoErr("cannot decrypt".into()));
    }
    Ok(output)
  }
}
