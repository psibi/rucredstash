// use crate::DynamoResult;
use aes_ctr::stream_cipher::generic_array::GenericArray;
use aes_ctr::stream_cipher::{NewStreamCipher, SyncStreamCipher, SyncStreamCipherSeek};
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
        &self,
        hmac_key: &hmac::Key,
        ciphertext: &Vec<u8>,
        hmac: &Vec<u8>,
    ) -> bool {
        match hmac::verify(&hmac_key, ciphertext.as_ref(), hmac.as_ref()) {
            Ok(()) => true,
            Err(_) => false,
        }
    }

    // fn decrypt_credstash(self, row: DynamoResult) -> () {
    //     ()
    // }

    pub fn aes_encrypt_ctr(self, plaintext: Vec<u8>, key: bytes::Bytes) -> Vec<u8> {
        // credstash uses AES symmetric encryption in CTR mode.
        // The key size used is 32 bytes (256 bits).
        let cipher_key: &GenericArray<u8, _> = GenericArray::from_slice(&key);
        let nonce: &GenericArray<u8, _> = GenericArray::from_slice(&self.default_nonce);
        let mut cipher = Aes256Ctr::new(&cipher_key, &nonce);
        let mut c1 = plaintext.clone();
        let f: &mut [u8] = unsafe {
            let c2: &mut [u8] = c1.as_mut();
            cipher.apply_keystream(c2);
            c2
        };
        // let g : String = std::str::from_utf8_mut(f).unwrap().to_string();
        f.to_vec()
    }

    fn aes_decrypt_ctr(self, ciphertext: String, key: String) -> String {
        let cipher_key: &GenericArray<u8, _> = GenericArray::from_slice(key.as_bytes());
        let nonce: &GenericArray<u8, _> = GenericArray::from_slice(&self.default_nonce);
        let mut cipher = Aes256Ctr::new(&cipher_key, &nonce);
        let mut c1 = ciphertext.clone();
        let f: &mut [u8] = unsafe {
            let c2: &mut [u8] = c1.as_bytes_mut();
            cipher.apply_keystream(c2);
            c2
        };
        let g: String = std::str::from_utf8_mut(f).unwrap().to_string();
        g
    }

    fn aes_decrypt_ctr2(self, ciphertext: Vec<u8>, key: String) -> String {
        let cipher_key: &GenericArray<u8, _> = GenericArray::from_slice(key.as_bytes());
        let nonce: &GenericArray<u8, _> = GenericArray::from_slice(&self.default_nonce);
        let mut cipher = Aes256Ctr::new(&cipher_key, &nonce);
        let mut c1 = ciphertext.clone();
        let f: &mut [u8] = unsafe {
            let c2: &mut [u8] = c1.as_mut();
            cipher.apply_keystream(c2);
            c2
        };
        let g: String = std::str::from_utf8_mut(f).unwrap().to_string();
        g
    }

    pub fn aes_decrypt_ctr3(self, ciphertext: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
        let cipher_key: &GenericArray<u8, _> = GenericArray::from_slice(&key[0..]);
        let nonce: &GenericArray<u8, _> = GenericArray::from_slice(&self.default_nonce);
        let mut cipher = Aes256Ctr::new(&cipher_key, &nonce);
        let mut c1 = ciphertext.clone();
        let f: &mut [u8] = unsafe {
            let c2: &mut [u8] = c1.as_mut();
            cipher.apply_keystream(c2);
            c2
        };
        // let g = f.to_owned();

        // let g: String = std::str::from_utf8_mut(f).unwrap().to_string();
        // g
        // f.iter().cloned().collect()
        f.to_vec()
    }

    // fn encrypt(plaintext: String, key: String, nonce: String)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decryption_works() {
        let crypto_context = Crypto::new();
        let key = "abcdefghijklmnopabcdefghijklmnop".to_string();
        let data: Vec<u8> = vec![163, 241, 173, 107, 241];
        let decrypt_value = crypto_context.aes_decrypt_ctr2(data, key);
        assert_eq!(decrypt_value, "hello".to_string());
    }
}
