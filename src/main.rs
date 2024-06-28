//! # Enc_File
//!
//! Encrypt / decrypt files or calculate hash from the command line.
//! Warning: This crate hasn't been audited or reviewed in any sense. I created it to easily encrypt und decrypt non-important files which won't cause harm if known by third parties. Don't use for anything important, use VeraCrypt or similar instead.
//!
//! Breaking change in Version 0.3: Changed input of some functions. To encrypt/decrypt and hash use e.g. "encrypt_chacha(readfile(example.file).unwrap(), key).unwrap()". Using a keymap to work with several keys conveniently. You can import your old keys, using "Add key" -> "manually".
//!
//! Breaking change in Version 0.2: Using XChaCha20Poly1305 as default encryption/decryption. AES is still available using encrypt_aes or decrypt_aes to maintain backwards compability.
//!
//! Uses XChaCha20Poly1305 (https://docs.rs/chacha20poly1305) or AES-GCM-SIV (https://docs.rs/aes-gcm-siv) for encryption/decryption, bincode (https://docs.rs/bincode) for encoding and BLAKE3 (https://docs.rs/blake3) or SHA256 / SHA512 (https://docs.rs/sha2) for hashing.
//!
//! Encrypted files are (and have to be) stored as .crpt.
//!
//! Panics at errors making execution impossible.  
//!
//! Can be used as library and a binary target. Install via cargo install enc_file
//! # Examples
//!
//! ```
//! use chacha_poly::{encrypt_chacha, decrypt_chacha, read_file};
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
//! let ciphertext = encrypt_chacha(text_vec, key).unwrap(); //encrypt vec<u8>, returns result(Vec<u8>)
//! //let ciphertext = encrypt_chacha(read_file(example.file).unwrap(), key).unwrap(); //read a file as Vec<u8> and then encrypt
//! //Check that plaintext != ciphertext
//! assert_ne!(&ciphertext, &text);
//!
//! //Decrypt ciphertext to plaintext
//! let plaintext = decrypt_chacha(ciphertext, key).unwrap();
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
//!assert_ne!(hash1, hash3); //check that the added "." changes the hash
//! ```
//!
//! See https://github.com/LazyEmpiricist/enc_file
//!

// Warning: Don't use for anything important! This crate hasn't been audited or reviewed in any sense. I created it to easily encrypt und decrypt non-important files which won't cause harm if known by third parties.
//
// Breaking change in Version 0.3: Using a keymap to work with several keys conveniently. You can import your old keys, using "Add key" and choose "manually".
//
// Breaking change in Version 0.2: Using XChaCha20Poly1305 as default encryption/decryption. AES is still available using encrypt_aes or decrypt_aes to maintain backwards compability.
//
// Uses XChaCha20Poly1305 (https://docs.rs/chacha20poly1305) or AES-GCM-SIV (https://docs.rs/aes-gcm-siv) for cryptography, bincode (https://docs.rs/bincode) for encoding and BLAKE3 (https://docs.rs/blake3) or SHA256 / SHA512 (https://docs.rs/sha2) for hashing.
//
// Generate a new key.file on first run (you can also manually add keys).
//
// Encrypting "example.file" will create a new (encrypted) file "example.file.crpt" in the same directory.
//
// Decrypting "example.file.crpt" will create a new (decrypted) file "example.file" in the same directory.
//
// Warning: Both encrypt and decrypt override existing files!
//
//
// # Examples
//
// Encrypt/decrypt using XChaCha20Poly1305 and random nonce
// ```
// use chacha_poly::{encrypt_chacha, decrypt_chacha, read_file};
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
// //let ciphertext = encrypt_chacha(read_file(example.file).unwrap(), key).unwrap(); //read a file as Vec<u8> and then encrypt
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

use std::fs;
use std::path::PathBuf;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use clap::Parser;

use chacha_poly::{create_new_keyfile, encrypt_chacha, parse_key};

/// Program description goes here
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Input file to be encrypted
    #[arg(short, long, alias = "input")]
    input_file: PathBuf,
    /// Output file to be generated [default: input_file.crpt]
    #[arg(short, long, alias = "output")]
    output_file: Option<PathBuf>,
    /// Encryption key file that stores key for encryption [default: key.file]
    #[arg(short, long, alias = "enc")]
    enc_key_file: PathBuf,
    /// Password to open the encryption key file
    #[arg(short, long, alias = "pw", default_value = "password")]
    password: String,
}

fn main() -> eyre::Result<()> {
    let args = Args::parse();
    let enc_key_file = args.enc_key_file;
    let input_file = args.input_file;
    // gather file dir
    let default_output_file = PathBuf::from(format!("{}.crpt", input_file.display()));
    let output_file = args.output_file.unwrap_or(default_output_file);

    // get input and key
    let Ok(input_plaintext) = fs::read(&input_file) else {
        eyre::bail!("failed reading input file");
    };
    let secret_key = match fs::read(&enc_key_file) {
        Ok(encoded) => parse_key(encoded, args.password.clone())?,
        // generate new key
        Err(_) => {
            println!("could not open {}", enc_key_file.display());
            let key = create_new_keyfile(args.password.clone(), &enc_key_file)?;
            println!(
                "generated new encryption key: {} in {}",
                key,
                enc_key_file.display()
            );
            key.into_bytes()
        }
    };
    // encrypt the input file into output file
    let encrypted = encrypt_chacha(&input_plaintext, &secret_key)?;
    let encrypted = BASE64_STANDARD.encode(encrypted);
    fs::write(&output_file, &encrypted)?;
    println!("saved to file: {}", output_file.display());
    println!("{}", encrypted);

    Ok(())
}
