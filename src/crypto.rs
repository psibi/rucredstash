use aes_ctr::stream_cipher::generic_array::GenericArray;
use aes_ctr::stream_cipher::{NewStreamCipher, SyncStreamCipher};
use aes_ctr::Aes256Ctr;
use ring::hmac;

pub struct Crypto {
    default_nonce: [u8; 16],
}

impl Crypto {
    pub fn new() -> Self {
        Crypto {
            default_nonce: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        }
    }

    pub fn verify_ciphertext_integrity(
        hmac_key: &hmac::Key,
        ciphertext: &Vec<u8>,
        hmac: &Vec<u8>,
    ) -> bool {
        match hmac::verify(hmac_key, ciphertext, hmac) {
            Ok(()) => true,
            Err(_) => false,
        }
    }

    pub fn aes_encrypt_ctr(self, plaintext: Vec<u8>, key: bytes::Bytes) -> Vec<u8> {
        // credstash uses AES symmetric encryption in CTR mode.
        // The key size used is 32 bytes (256 bits).
        let cipher_key: &GenericArray<u8, _> = GenericArray::from_slice(&key);
        let nonce: &GenericArray<u8, _> = GenericArray::from_slice(&self.default_nonce);
        let mut cipher = Aes256Ctr::new(&cipher_key, &nonce);
        let mut plain_text = plaintext.clone();
        let cipher_text: &mut [u8] = plain_text.as_mut();
        cipher.apply_keystream(cipher_text);
        cipher_text.to_vec()
    }

    pub fn aes_decrypt_ctr(self, ciphertext: Vec<u8>, key: bytes::Bytes) -> Vec<u8> {
        let cipher_key: &GenericArray<u8, _> = GenericArray::from_slice(&key[0..]);
        let nonce: &GenericArray<u8, _> = GenericArray::from_slice(&self.default_nonce);
        let mut cipher = Aes256Ctr::new(&cipher_key, &nonce);
        let mut cipher_text = ciphertext.clone();
        let plain_text: &mut [u8] = cipher_text.as_mut();
        cipher.apply_keystream(plain_text);
        plain_text.to_vec()
    }
}

#[test]
fn aes_encrypt_check() {
    let crypto = Crypto::new();
    let key = bytes::Bytes::from_static(b"secretkeysecretkeysecretkeysecre");
    let plaintext: Vec<u8> = "helloworld".as_bytes().to_vec();
    assert_eq!(
        crypto.aes_encrypt_ctr(plaintext, key),
        vec![248, 192, 8, 240, 148, 247, 69, 193, 93, 58]
    );
}

#[test]
fn aes_decrypt_check() {
    let crypto = Crypto::new();
    let key = bytes::Bytes::from_static(b"secretkeysecretkeysecretkeysecre");
    let ciphertext: Vec<u8> = vec![248, 192, 8, 240, 148, 247, 69, 193, 93, 58];
    assert_eq!(
        crypto.aes_decrypt_ctr(ciphertext, key),
        "helloworld".as_bytes().to_vec()
    );
}
