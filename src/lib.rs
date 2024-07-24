//! # Enc_File
//!
//! Encrypt / decrypt files or calculate hash from the command line.
//! Warning: This crate hasn't been audited or reviewed in any sense. I created it to easily encrypt und decrypt non-important files which won't cause harm if known by third parties. Don't use for anything important, use VeraCrypt or similar instead.
//!
//! Breaking change in Version 0.3: Changed input of some functions. To encrypt/decrypt and hash use e.g. "encrypt_chacha(readfile(example.file).unwrap(), key).unwrap()". Using a keymap to work with several keys conveniently. You can import your old keys, using "Add key" -> "manually".
//!
//! Breaking change in Version 0.2: Using XChaCha20Poly1305 as default encryption/decryption. AES is still available using encrypt_aes or decrypt_aes to maintain backwards compability.
//!
//! Uses XChaCha20Poly1305 (https://docs.rs/chacha20poly1305) or AES-GCM-SIV (https://docs.rs/aes-gcm-siv) for encryption, bincode (https://docs.rs/bincode) for encoding and BLAKE3 (https://docs.rs/blake3) or SHA256 / SHA512 (https://docs.rs/sha2) for hashing.
//!
//! Encrypted files are (and have to be) stored as .crpt.
//!
//! Can be used as library and a binary target. Install via cargo install enc_file
//!
//! Panics at errors making safe execution impossible.  
//!
//! # Examples
//!
//! ```
//! use chacha_poly::{encrypt_chacha, decrypt_chacha};
//!
//! //Plaintext to encrypt
//! let text = b"This a test";
//! //Provide key. Key will normally be chosen from keymap and provided to the encrypt_chacha() function
//! let key: &str = "an example very very secret key.";
//! //Convert text to Vec<u8>
//! let text_vec = text.to_vec();
//!
//! //Encrypt text
//! //Ciphertext stores the len() of encrypted content, the nonce and the actual ciphertext using bincode
//! let ciphertext = encrypt_chacha(text, key.as_bytes()).unwrap(); //encrypt vec<u8>, returns result(Vec<u8>)
//! //let ciphertext = encrypt_chacha(read_file_as_vec_u8(example.file).unwrap(), key).unwrap(); //read a file as Vec<u8> and then encrypt
//! //Check that plaintext != ciphertext
//! assert_ne!(&ciphertext, &text);
//!
//! //Decrypt ciphertext to plaintext
//! let plaintext = decrypt_chacha(&ciphertext, key.as_bytes()).unwrap();
//! //Check that text == plaintext
//! assert_eq!(format!("{:?}", text), format!("{:?}", plaintext));
//! ```
//!
//! ```
//!use chacha_poly::{get_blake3_hash};
//!
//!let test = b"Calculating the BLAKE3 Hash of this text";
//!let test_vec = test.to_vec(); //Convert text to Vec<u8>
//!let hash1 = get_blake3_hash(test_vec.clone()).unwrap();
//!let hash2 = get_blake3_hash(test_vec).unwrap();
//!assert_eq!(hash1, hash2); //Make sure hash1 == hash2
//!let test2 = b"Calculating the BLAKE3 Hash of this text."; //"." added at the end
//!let test2_vec = test2.to_vec();
//!let hash3 = get_blake3_hash(test2_vec).unwrap();
//!assert_ne!(hash1, hash3); //check that the added "." changes the hash and hash1 != hash3
//! ```
//!
//! See https://github.com/LazyEmpiricist/enc_file
//!

// Warning: Don't use for anything important! This crate hasn't been audited or reviewed in any sense. I created it to easily encrypt und decrypt non-important files which won't cause harm if known by third parties.
//
// Breaking change in Version 0.2: Using XChaCha20Poly1305 as default encryption/decryption. AES is still available using encrypt_aes or decrypt_aes to maintain backwards compability. //
//
// Uses XChaCha20Poly1305 (https://docs.rs/chacha20poly1305) or AES-GCM-SIV (https://docs.rs/aes-gcm-siv) for encryption, bincode (https://docs.rs/bincode) for encoding and BLAKE3 (https://docs.rs/blake3) or SHA256 / SHA512 (https://docs.rs/sha2) for hashing.
//
// Generate a new key.file on first run (you can also manually add keys).
//
// Encrypting "example.file" will create a new (encrypted) file "example.file.crpt" in the same directory.
//
// Decrypting "example.file.crpt" will create a new (decrypted) file "example.file" in the same directory.
//
// Both encrypt and decrypt override existing files!
//
//
// # Examples
//
// Encrypt/decrypt using XChaCha20Poly1305 and random nonce
// ```
// use chacha_poly::{encrypt_chacha, decrypt_chacha, read_file_as_vec_u8};
//
// //Plaintext to encrypt
// let text = b"This a test";
// //Provide key. Key will normally be chosen from keymap and provided to the encrypt_chacha() function
// let key: &str = "an example very very secret key.";
// //Convert text to Vec<u8>
// let text_vec = text.to_vec();
//
// //Encrypt text
// let ciphertext = encrypt_chacha(text_vec, key).unwrap(); //encrypt vec<u8>, returns result(Vec<u8>)
// //let ciphertext = encrypt_chacha(read_file_as_vec_u8(example.file).unwrap(), key).unwrap(); //read a file as Vec<u8> and then encrypt
// //Check that plaintext != ciphertext
// assert_ne!(&ciphertext, &text);
//
// //Decrypt ciphertext to plaintext
// let plaintext = decrypt_chacha(ciphertext, key).unwrap();
// //Check that text == plaintext
// assert_eq!(format!("{:?}", text), format!("{:?}", plaintext));
// ```
//
// Calculate Blake3 Hash
// ```
// use chacha_poly::{get_blake3_hash};
//
// let test = b"Calculating the BLAKE3 Hash of this text";
// let test_vec = test.to_vec(); //Convert text to Vec<u8>
// let hash1 = get_blake3_hash(test_vec.clone()).unwrap();
// let hash2 = get_blake3_hash(test_vec).unwrap();
// assert_eq!(hash1, hash2); //Make sure hash1 == hash2
// ```

#[cfg(target_os = "windows")]
compile_error!("This crate is not supported on Windows");

use std::io;
use std::iter;

use aes_gcm_siv::aead::{Aead, KeyInit};
use aes_gcm_siv::{Aes256GcmSiv, Nonce as AES_Nonce};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use eyre::{bail, eyre};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};

//Struct to store ciphertext, nonce and ciphertext.len() in file and to read it from file
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Cipher {
    len: usize,
    rand_string: String,
    ciphertext: Vec<u8>,
}

/// Encrypts cleartext (Vec<u8>) with a key (&str) using XChaCha20Poly1305 (24-byte nonce as compared to 12-byte in ChaCha20Poly1305). Returns result (ciphertext as Vec<u8>).
///
/// # Examples
///
/// ```
/// use chacha_poly::{encrypt_chacha, decrypt_chacha};
///
/// let text = b"This a test";
/// let key: &str = "an example very very secret key.";
/// // encrypt_chacha takes plaintext as Vec<u8>. Text needs to be transformed into vector
/// let text_vec = text.to_vec();
///
/// let ciphertext = encrypt_chacha(text, key.as_bytes()).unwrap();
/// assert_ne!(&ciphertext, &text);
///
/// let plaintext = decrypt_chacha(&ciphertext, key.as_bytes()).unwrap();
/// assert_eq!(format!("{:?}", text), format!("{:?}", plaintext));
/// ```
pub fn encrypt_chacha(cleartext: &[u8], secret_key: &[u8]) -> eyre::Result<Vec<u8>> {
    let aead = XChaCha20Poly1305::new_from_slice(secret_key)?;
    //generate random nonce
    let mut rng = thread_rng();
    let rand_string: String = iter::repeat(())
        .map(|()| rng.sample(Alphanumeric))
        .map(char::from)
        .take(24)
        .collect();
    let nonce = XNonce::from_slice(rand_string.as_bytes());
    let ciphertext: Vec<u8> = aead
        .encrypt(nonce, cleartext)
        .map_err(|_| eyre!("encryption failure!"))?;
    //ciphertext_to_send includes the length of the ciphertext (to confirm upon decryption), the nonce (needed to decrypt) and the actual ciphertext
    let ciphertext_to_send = Cipher {
        len: ciphertext.len(),
        rand_string,
        ciphertext,
    };
    //serialize using bincode. Facilitates storing in file.
    let encoded: Vec<u8> = bincode::serialize(&ciphertext_to_send)?;
    Ok(encoded)
}

/// Decrypts ciphertext (Vec<u8>) with a key (&str) using XChaCha20Poly1305 (24-byte nonce as compared to 12-byte in ChaCha20Poly1305). Panics with wrong key. Returns result (cleartext as Vec<u8>).
///
/// # Examples
///
/// ```
/// use chacha_poly::{encrypt_chacha, decrypt_chacha};
///
/// let text = b"This a test";
/// let key: &str = "an example very very secret key.";
/// // encrypt_chacha takes plaintext as Vec<u8>. Text needs to be transformed into vector
/// let text_vec = text.to_vec();
///
/// let ciphertext = encrypt_chacha(text, key.as_bytes()).unwrap();
/// assert_ne!(&ciphertext, &text);
///
/// let plaintext = decrypt_chacha(&ciphertext, key.as_bytes()).unwrap();
/// assert_eq!(format!("{:?}", text), format!("{:?}", plaintext));
/// ```
pub fn decrypt_chacha(enc: &[u8], key: &[u8]) -> eyre::Result<Vec<u8>> {
    let aead = XChaCha20Poly1305::new_from_slice(key)?;

    //deserialize input read from file
    let decoded: Cipher = bincode::deserialize(enc)?;
    let (ciphertext2, len_ciphertext, rand_string2) =
        (decoded.ciphertext, decoded.len, decoded.rand_string);
    //check if included length of ciphertext == actual length of ciphertext
    if ciphertext2.len() != len_ciphertext {
        bail!("length of received ciphertext not ok")
    };
    let nonce = XNonce::from_slice(rand_string2.as_bytes());
    //decrypt to plaintext
    let plaintext: Vec<u8> = aead
        .decrypt(nonce, ciphertext2.as_ref())
        .map_err(|_| eyre!("decryption failure!"))?;
    Ok(plaintext)
}

// Encrypts cleartext (Vec<u8>) with a key (&str) using AES256 GCM SIV. Returns result (ciphertext as Vec<u8>).
///
/// # Examples
///
/// ```
/// use chacha_poly::{encrypt_aes, decrypt_aes};
///
/// let text = b"This a test";
/// let key: &str = "an example very very secret key.";
/// // encrypt_aes takes plaintext as Vec<u8>. Text needs to be transformed into vector
/// let text_vec = text.to_vec();
///
/// let ciphertext = encrypt_aes(text, key).unwrap();
/// assert_ne!(&ciphertext, &text);
///
/// let plaintext = decrypt_aes(ciphertext, key).unwrap();
/// assert_eq!(format!("{:?}", text), format!("{:?}", plaintext));
/// ```
pub fn encrypt_aes(cleartext: &[u8], key: &str) -> eyre::Result<Vec<u8>> {
    let aead = Aes256GcmSiv::new_from_slice(key.as_bytes())?;
    //generate random nonce
    let mut rng = thread_rng();
    let rand_string: String = iter::repeat(())
        .map(|()| rng.sample(Alphanumeric))
        .map(char::from)
        .take(12)
        .collect();
    let nonce = AES_Nonce::from_slice(rand_string.as_bytes());
    let ciphertext: Vec<u8> = aead.encrypt(nonce, cleartext).expect("encryption failure!");
    //ciphertext_to_send includes the length of the ciphertext (to confirm upon decryption), the nonce (needed to decrypt) and the actual ciphertext
    let ciphertext_to_send = Cipher {
        len: ciphertext.len(),
        rand_string,
        ciphertext,
    };
    //serialize using bincode. Facilitates storing in file.
    let encoded: Vec<u8> = bincode::serialize(&ciphertext_to_send)?;
    Ok(encoded)
}

/// Decrypts ciphertext (Vec<u8>) with a key (&str) using AES256 GCM SIV. Panics with wrong key. Returns result (cleartext as Vec<u8>).
///
/// # Examples
///
/// ```
/// use chacha_poly::{encrypt_aes, decrypt_aes};
///
/// let text = b"This a test";
/// let key: &str = "an example very very secret key.";
/// // encrypt_aes takes plaintext as Vec<u8>. Text needs to be transformed into vector
/// let text_vec = text.to_vec();
///
/// let ciphertext = encrypt_aes(text, key).unwrap();
/// assert_ne!(&ciphertext, &text);
///
/// let plaintext = decrypt_aes(ciphertext, key).unwrap();
/// assert_eq!(format!("{:?}", text), format!("{:?}", plaintext));
/// ```
pub fn decrypt_aes(enc: Vec<u8>, key: &str) -> eyre::Result<Vec<u8>> {
    let aead = Aes256GcmSiv::new_from_slice(key.as_bytes())?;
    //deserialize input read from file
    let decoded: Cipher = bincode::deserialize(&enc[..])?;
    let (ciphertext2, len_ciphertext, rand_string2) =
        (decoded.ciphertext, decoded.len, decoded.rand_string);
    //check if included length of ciphertext == actual length of ciphertext
    if ciphertext2.len() != len_ciphertext {
        panic!("length of received ciphertext not ok")
    };
    let nonce = AES_Nonce::from_slice(rand_string2.as_bytes());
    //decrypt to plaintext
    let plaintext: Vec<u8> = aead
        .decrypt(nonce, ciphertext2.as_ref())
        .expect("decryption failure!");
    Ok(plaintext)
}

/// Reads userinput from stdin and returns it as String. Returns result.
pub fn get_input_string() -> eyre::Result<String> {
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let trimmed = input.trim().to_string();
    Ok(trimmed)
}

/// Get BLAKE3 Hash from data. File needs to be read as Vec<u8> (e.g. use chacha_poly::read_file_as_vec_u8()). Returns result.
/// Uses multithreading if len(Vec<u8>) > 128.000
/// # Examples
///
/// ```
/// use chacha_poly::{get_blake3_hash};
///
/// //creating to different Vec<u8> to hash and compare
/// let test = b"Calculating the BLAKE3 Hash of this text".to_vec();
/// let test2 = b"Calculating the BLAKE3 Hash of this different text".to_vec();
///
/// //hashing 2x test and 1x test2 to compare the hashes. hash1 == hash2 != hash3
/// let hash1 = get_blake3_hash(test.clone()).unwrap();
/// let hash2 = get_blake3_hash(test).unwrap();
/// let hash3 = get_blake3_hash(test2).unwrap();
/// assert_eq!(hash1, hash2);
/// assert_ne!(hash1, hash3);
/// ```
pub fn get_blake3_hash(data: Vec<u8>) -> eyre::Result<blake3::Hash> {
    //check len() of Vec<u8> and for big files use rayon to improve compute time utilizing threads
    let hash: blake3::Hash = if data.len() < 128000 {
        blake3::hash(&data)
    } else {
        let input: &[u8] = &data;
        let mut hasher = blake3::Hasher::new();
        hasher.update_rayon(input);
        hasher.finalize()
    };
    Ok(hash)
}

/// Get SHA2-256 Hash from data. File needs to be read as Vec<u8> (e.g. use chacha_poly::read_file_as_vec_u8()). Returns result.
/// # Examples
///
/// ```
/// use chacha_poly::{get_sha2_256_hash};
///
/// //creating to different Vec<u8> to hash and compare
/// let test = b"Calculating the SHA2-256 Hash of this text".to_vec();
/// let test2 = b"Calculating the the SHA2-256 Hash of this different text".to_vec();
///
/// //hashing 2x test and 1x test2 to compare the hashes. hash1 == hash2 != hash3
/// let hash1 = get_sha2_256_hash(test.clone()).unwrap();
/// let hash2 = get_sha2_256_hash(test).unwrap();
/// let hash3 = get_sha2_256_hash(test2).unwrap();
/// assert_eq!(hash1, hash2);
/// assert_ne!(hash1, hash3);
/// ```
pub fn get_sha2_256_hash(data: Vec<u8>) -> eyre::Result<String> {
    use sha2::{Digest, Sha256};

    // create a Sha256 object
    let mut hasher = Sha256::new();

    // write input message
    hasher.update(data);

    // read hash digest and consume hasher
    let hash = hasher.finalize();
    Ok(format!("{:?}", hash))
}

/// Get SHA2-512 Hash from data. File needs to be read as Vec<u8> (e.g. use chacha_poly::read_file_as_vec_u8()). Returns result.
/// # Examples
///
/// ```
/// use chacha_poly::{get_sha2_512_hash};
///
/// //creating to different Vec<u8> to hash and compare
/// let test = b"Calculating the the SHA2-512 Hash of this text".to_vec();
/// let test2 = b"Calculating the SHA2-512 Hash of this different text".to_vec();
///
/// //hashing 2x test and 1x test2 to compare the hashes. hash1 == hash2 != hash3
/// let hash1 = get_sha2_512_hash(test.clone()).unwrap();
/// let hash2 = get_sha2_512_hash(test).unwrap();
/// let hash3 = get_sha2_512_hash(test2).unwrap();
/// assert_eq!(hash1, hash2);
/// assert_ne!(hash1, hash3);
/// ```
pub fn get_sha2_512_hash(data: Vec<u8>) -> eyre::Result<String> {
    use sha2::{Digest, Sha512};

    // create a Sha256 object
    let mut hasher = Sha512::new();

    // write input message
    hasher.update(data);

    // read hash digest and consume hasher
    let hash = hasher.finalize();
    Ok(format!("{:?}", hash))
}

/// Get SHA3-256 Hash from data. File needs to be read as Vec<u8> (e.g. use chacha_poly::read_file_as_vec_u8()). Returns result.
/// # Examples
///
/// ```
/// use chacha_poly::{get_sha3_256_hash};
///
/// //creating to different Vec<u8> to hash and compare
/// let test = b"Calculating the the SHA3-256 Hash of this text".to_vec();
/// let test2 = b"Calculating the SHA3-256 Hash of this different text".to_vec();
///
/// //hashing 2x test and 1x test2 to compare the hashes. hash1 == hash2 != hash3
/// let hash1 = get_sha3_256_hash(test.clone()).unwrap();
/// let hash2 = get_sha3_256_hash(test).unwrap();
/// let hash3 = get_sha3_256_hash(test2).unwrap();
/// assert_eq!(hash1, hash2);
/// assert_ne!(hash1, hash3);
/// ```
pub fn get_sha3_256_hash(data: Vec<u8>) -> eyre::Result<String> {
    use sha3::{Digest, Sha3_256};

    // create a Sha256 object
    let mut hasher = Sha3_256::new();

    // write input message
    hasher.update(data);

    // read hash digest and consume hasher
    let hash = hasher.finalize();
    Ok(format!("{:?}", hash))
}

/// Get SHA3-512 Hash from data. File needs to be read as Vec<u8> (e.g. use chacha_poly::read_file_as_vec_u8()). Returns result.
/// # Examples
///
/// ```
/// use chacha_poly::{get_sha3_512_hash};
///
/// //creating to different Vec<u8> to hash and compare
/// let test = b"Calculating the the SHA3-512 Hash of this text".to_vec();
/// let test2 = b"Calculating the SHA3-512 Hash of this different text".to_vec();
///
/// //hashing 2x test and 1x test2 to compare the hashes. hash1 == hash2 != hash3
/// let hash1 = get_sha3_512_hash(test.clone()).unwrap();
/// let hash2 = get_sha3_512_hash(test).unwrap();
/// let hash3 = get_sha3_512_hash(test2).unwrap();
/// assert_eq!(hash1, hash2);
/// assert_ne!(hash1, hash3);
/// ```
pub fn get_sha3_512_hash(data: Vec<u8>) -> eyre::Result<String> {
    use sha3::{Digest, Sha3_512};

    // create a Sha256 object
    let mut hasher = Sha3_512::new();

    // write input message
    hasher.update(data);

    // read hash digest and consume hasher
    let hash = hasher.finalize();
    Ok(format!("{:?}", hash))
}
pub const PASSWORD_LEN: usize = 32;
pub fn gen_rand_password() -> String {
    let mut rng = thread_rng();
    let key_rand: String = iter::repeat(())
        .map(|()| rng.sample(Alphanumeric))
        .map(char::from)
        .take(PASSWORD_LEN)
        .collect();
    key_rand
}

#[cfg(test)]
mod tests {
    use base64::prelude::BASE64_STANDARD;
    use base64::Engine;

    use super::*;

    #[test]
    fn test_encryt_decrypt_aes() {
        let text = b"This a test";
        let key: &str = "an example very very secret key.";
        let ciphertext = encrypt_aes(text, key).unwrap();
        assert_ne!(&ciphertext, &text);
        let plaintext = decrypt_aes(ciphertext, key).unwrap();
        assert_eq!(format!("{:?}", text), format!("{:?}", plaintext));
    }

    #[test]
    fn test_encryt_decrypt_chacha() {
        let text = b"This a test";
        let key: &str = "an example very very secret key.";
        let ciphertext = encrypt_chacha(text, key.as_bytes()).unwrap();
        assert_ne!(&ciphertext, &text);
        let plaintext = decrypt_chacha(&ciphertext, key.as_bytes()).unwrap();
        assert_eq!(format!("{:?}", text), format!("{:?}", plaintext));
    }

    #[test]
    fn test_multiple_encrypt_unequal_chacha() {
        use rand::{distributions::Uniform, Rng};
        let range = Uniform::new(0, 255);

        let mut i = 1;
        while i < 1000 {
            let mut rng = thread_rng();
            let key: String = iter::repeat(())
                .map(|()| rng.sample(Alphanumeric))
                .map(char::from)
                .take(32)
                .collect();
            let content: Vec<u8> = (0..100).map(|_| rng.sample(&range)).collect();
            let ciphertext1 = encrypt_chacha(&content, key.as_bytes()).unwrap();
            let ciphertext2 = encrypt_chacha(&content, key.as_bytes()).unwrap();
            let ciphertext3 = encrypt_chacha(&content, key.as_bytes()).unwrap();
            let ciphertext4 = encrypt_chacha(&content, key.as_bytes()).unwrap();
            let ciphertext5 = encrypt_chacha(&content, key.as_bytes()).unwrap();
            assert_ne!(&ciphertext1, &ciphertext2);
            assert_ne!(&ciphertext1, &ciphertext3);
            assert_ne!(&ciphertext1, &ciphertext4);
            assert_ne!(&ciphertext1, &ciphertext5);
            assert_ne!(&ciphertext2, &ciphertext3);
            assert_ne!(&ciphertext2, &ciphertext4);
            assert_ne!(&ciphertext2, &ciphertext5);
            assert_ne!(&ciphertext3, &ciphertext4);
            assert_ne!(&ciphertext3, &ciphertext5);
            assert_ne!(&ciphertext4, &ciphertext5);
            i += 1;
        }
    }

    #[test]
    fn test_multiple_encrypt_unequal_aes() {
        use rand::{distributions::Uniform, Rng};
        let range = Uniform::new(0, 255);
        let mut i = 1;
        while i < 1000 {
            let mut rng = thread_rng();
            let key: String = iter::repeat(())
                .map(|()| rng.sample(Alphanumeric))
                .map(char::from)
                .take(32)
                .collect();
            let content: Vec<u8> = (0..100).map(|_| rng.sample(&range)).collect();
            let ciphertext1 = encrypt_aes(&content, &key).unwrap();
            let ciphertext2 = encrypt_aes(&content, &key).unwrap();
            let ciphertext3 = encrypt_aes(&content, &key).unwrap();
            let ciphertext4 = encrypt_aes(&content, &key).unwrap();
            let ciphertext5 = encrypt_aes(&content, &key).unwrap();
            assert_ne!(&ciphertext1, &ciphertext2);
            assert_ne!(&ciphertext1, &ciphertext3);
            assert_ne!(&ciphertext1, &ciphertext4);
            assert_ne!(&ciphertext1, &ciphertext5);
            assert_ne!(&ciphertext2, &ciphertext3);
            assert_ne!(&ciphertext2, &ciphertext4);
            assert_ne!(&ciphertext2, &ciphertext5);
            assert_ne!(&ciphertext3, &ciphertext4);
            assert_ne!(&ciphertext3, &ciphertext5);
            assert_ne!(&ciphertext4, &ciphertext5);
            i += 1;
        }
    }

    #[test]
    fn test_hash_blake3() {
        let test = b"Calculating the BLAKE3 Hash of this text".to_vec();
        let test2 = b"Calculating the BLAKE3 Hash of this different text".to_vec();
        let hash1 = get_blake3_hash(test.clone()).unwrap();
        let hash2 = get_blake3_hash(test).unwrap();
        let hash3 = get_blake3_hash(test2).unwrap();
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_hash_blake3_big() {
        //testing large data input with Blake3 hashing function using rayon implementation
        let random_bytes: Vec<u8> = (0..128000).map(|_| rand::random::<u8>()).collect();
        let random_bytes2: Vec<u8> = (0..128000).map(|_| rand::random::<u8>()).collect();
        let hash1 = get_blake3_hash(random_bytes.clone()).unwrap();
        let hash2 = get_blake3_hash(random_bytes).unwrap();
        let hash3 = get_blake3_hash(random_bytes2).unwrap();
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_hash_sha2_256() {
        let test = b"Calculating the Hash of this text".to_vec();
        let test2 = b"Calculating the Hash of this different text".to_vec();
        let hash1 = get_sha2_256_hash(test.clone()).unwrap();
        let hash2 = get_sha2_256_hash(test).unwrap();
        let hash3 = get_sha2_256_hash(test2).unwrap();
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_hash_sha2_512() {
        let test = b"Calculating the Hash of this text".to_vec();
        let test2 = b"Calculating the Hash of this different text".to_vec();
        let hash1 = get_sha2_512_hash(test.clone()).unwrap();
        let hash2 = get_sha2_512_hash(test).unwrap();
        let hash3 = get_sha2_512_hash(test2).unwrap();
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_hash_sha3_256() {
        let test = b"Calculating the Hash of this text".to_vec();
        let test2 = b"Calculating the Hash of this different text".to_vec();
        let hash1 = get_sha3_256_hash(test.clone()).unwrap();
        let hash2 = get_sha3_256_hash(test).unwrap();
        let hash3 = get_sha3_256_hash(test2).unwrap();
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_hash_sha3_512() {
        let test = b"Calculating the Hash of this text".to_vec();
        let test2 = b"Calculating the Hash of this different text".to_vec();
        let hash1 = get_sha3_512_hash(test.clone()).unwrap();
        let hash2 = get_sha3_512_hash(test).unwrap();
        let hash3 = get_sha3_512_hash(test2).unwrap();
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_hash_sha_big() {
        //testing large data input with SHA2 and SHA3 hashing functions
        //testing SHA2-256
        let random_bytes: Vec<u8> = (0..128000).map(|_| rand::random::<u8>()).collect();
        let random_bytes2: Vec<u8> = (0..128000).map(|_| rand::random::<u8>()).collect();
        let hash1 = get_sha2_256_hash(random_bytes.clone()).unwrap();
        let hash2 = get_sha2_256_hash(random_bytes).unwrap();
        let hash3 = get_sha2_256_hash(random_bytes2).unwrap();
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
        //testing SHA2-512
        let random_bytes: Vec<u8> = (0..128000).map(|_| rand::random::<u8>()).collect();
        let random_bytes2: Vec<u8> = (0..128000).map(|_| rand::random::<u8>()).collect();
        let hash1 = get_sha2_512_hash(random_bytes.clone()).unwrap();
        let hash2 = get_sha2_512_hash(random_bytes).unwrap();
        let hash3 = get_sha2_512_hash(random_bytes2).unwrap();
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
        //testing SHA3-256
        let random_bytes: Vec<u8> = (0..128000).map(|_| rand::random::<u8>()).collect();
        let random_bytes2: Vec<u8> = (0..128000).map(|_| rand::random::<u8>()).collect();
        let hash1 = get_sha3_256_hash(random_bytes.clone()).unwrap();
        let hash2 = get_sha3_256_hash(random_bytes).unwrap();
        let hash3 = get_sha3_256_hash(random_bytes2).unwrap();
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
        //testing SHA3-512
        let random_bytes: Vec<u8> = (0..128000).map(|_| rand::random::<u8>()).collect();
        let random_bytes2: Vec<u8> = (0..128000).map(|_| rand::random::<u8>()).collect();
        let hash1 = get_sha3_512_hash(random_bytes.clone()).unwrap();
        let hash2 = get_sha3_512_hash(random_bytes).unwrap();
        let hash3 = get_sha3_512_hash(random_bytes2).unwrap();
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_multiple_random_chacha() {
        use rand::{distributions::Uniform, Rng};
        let range = Uniform::new(0, 255);
        let mut i = 1;
        while i < 1000 {
            let mut rng = thread_rng();
            let key: String = iter::repeat(())
                .map(|()| rng.sample(Alphanumeric))
                .map(char::from)
                .take(32)
                .collect();

            let content: Vec<u8> = (0..100).map(|_| rng.sample(&range)).collect();
            let ciphertext = encrypt_chacha(&content, key.as_bytes()).unwrap();
            assert_ne!(&ciphertext, &content);
            let plaintext = decrypt_chacha(&ciphertext, key.as_bytes()).unwrap();
            assert_eq!(format!("{:?}", content), format!("{:?}", plaintext));

            i += 1;
        }
    }

    #[test]
    fn test_multiple_random_aes() {
        use rand::{distributions::Uniform, Rng};
        let range = Uniform::new(0, 255);
        let mut i = 1;
        while i < 1000 {
            let mut rng = thread_rng();
            let key: String = iter::repeat(())
                .map(|()| rng.sample(Alphanumeric))
                .map(char::from)
                .take(32)
                .collect();

            let content: Vec<u8> = (0..100).map(|_| rng.sample(&range)).collect();
            let ciphertext = encrypt_aes(&content, &key).unwrap();
            assert_ne!(&ciphertext, &content);
            let plaintext = decrypt_aes(ciphertext, &key).unwrap();
            assert_eq!(format!("{:?}", content), format!("{:?}", plaintext));

            i += 1;
        }
    }
    #[test]
    fn test_example() {
        let text = b"This a test"; //Text to encrypt
        let key: &str = "an example very very secret key."; //Key will normally be chosen from keymap and provided to the encrypt_chacha() function
        let ciphertext = encrypt_chacha(text, key.as_bytes()).unwrap(); //encrypt vec<u8>, returns result(Vec<u8>)
                                                                        //let ciphertext = encrypt_chacha(read_file_as_vec_u8(example.file).unwrap(), key).unwrap(); //read a file as Vec<u8> and then encrypt
        assert_ne!(&ciphertext, &text); //Check that plaintext != ciphertext
        let plaintext = decrypt_chacha(&ciphertext, key.as_bytes()).unwrap(); //Decrypt ciphertext to plaintext
        assert_eq!(format!("{:?}", text), format!("{:?}", plaintext)); //Check that text == plaintext
    }

    #[test]
    #[should_panic]
    fn test_chacha_wrong_key_panic() {
        let text = b"This a another test"; //Text to encrypt
        let key: &str = "an example very very secret key."; //Key will normally be chosen from keymap and provided to the encrypt_chacha() function
        let ciphertext = encrypt_chacha(text, key.as_bytes()).unwrap(); //encrypt vec<u8>, returns result(Vec<u8>)

        assert_ne!(&ciphertext, &text); //Check that plaintext != ciphertext
        let key: &str = "an example very very secret key!"; //The ! should result in decryption panic
        let _plaintext = decrypt_chacha(ciphertext.as_ref(), key.as_bytes()).unwrap();
        //Decrypt ciphertext to plaintext
    }

    #[test]
    #[should_panic]
    fn test_aes_wrong_key_panic() {
        let text = b"This a another test"; //Text to encrypt
        let key: &str = "an example very very secret key."; //Key will normally be chosen from keymap and provided to the encrypt_chacha() function
        let ciphertext = encrypt_aes(text, key).unwrap(); //encrypt vec<u8>, returns result(Vec<u8>)
        assert_ne!(&ciphertext, &text); //Check that plaintext != ciphertext
        let key: &str = "an example very very secret key!"; //The ! should result in decryption panic
        let _plaintext = decrypt_aes(ciphertext, key).unwrap(); //Decrypt ciphertext to plaintext
    }

    #[test]
    fn test_example_hash() {
        let test = b"Calculating the BLAKE3 Hash of this text";
        let test_vec = test.to_vec(); //Convert text to Vec<u8>
        let hash1 = get_blake3_hash(test_vec.clone()).unwrap();
        let hash2 = get_blake3_hash(test_vec).unwrap();
        assert_eq!(hash1, hash2); //Make sure hash1 == hash2
        let test2 = b"Calculating the BLAKE3 Hash of this text."; //"." added at the end
        let test2_vec = test2.to_vec();
        let hash3 = get_blake3_hash(test2_vec).unwrap();
        //check that the added "." changes the hash
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn encrypt_decrypt() {
        use super::*;
        let plain_expected = "hello";
        let key = "iIFgasiZ0ZXwdffPyBKHjj3fLhfQ05gd";
        let ciphertext = "FQAAAAAAAAAYAAAAAAAAAFY5WGZUaTZlUzNybXlLRndHcEdBbEZhWhUAAAAAAAAAh4qZ680wLAnkEdcmRDD0oS5V8FCa";
        let plain_actual = BASE64_STANDARD.decode(ciphertext).unwrap();
        println!("decoded: {plain_actual:?}");
        let plain_actual = decrypt_chacha(&plain_actual, key.as_bytes()).unwrap();
        assert_eq!(plain_expected.as_bytes(), plain_actual);
    }
}
