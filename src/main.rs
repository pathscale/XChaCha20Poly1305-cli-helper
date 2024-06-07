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

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use chacha_poly::{
    add_key, choose_hashing_function, create_new_keyfile, create_new_keyfile_interactive,
    decrypt_file_procedual, encrypt_chacha, encrypt_file_procedual, get_input_string, parse_key,
    read_file_as_vec_u8, read_keyfile_interactive, remove_key, save_file,
};
use clap::Parser;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::str::FromStr;

/// Program description goes here
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// First parameter description
    #[arg(short, long, alias = "input")]
    input_file: Option<PathBuf>,
    /// Second parameter description
    #[arg(short, long, alias = "output")]
    output_file: Option<PathBuf>,
    /// Optional flag
    #[arg(short, long, alias = "enc")]
    enc_key_file: Option<PathBuf>,
    #[arg(short, long, alias = "pw", default_value = "password")]
    password: String,
    #[arg(short, long, default_value = "keyname")]
    keyname: String,
}

fn main() -> eyre::Result<()> {
    let args = Args::parse();
    match (args.input_file, args.output_file, args.enc_key_file) {
        // interactive mode
        (None, None, None) => loop {
            if let Err(e) = menu_selection() {
                println!("error: {e}");
            }
        },
        // direct encrypt mode
        (Some(input_file), output_file_opt, enc_key_file_opt) => {
            // gather file dir
            let default_output_file = PathBuf::from(format!("{}.crpt", input_file.display()));
            let default_enc_key_file = PathBuf::from_str("key.file")?;
            let output_file = output_file_opt.unwrap_or(default_output_file);
            let enc_key_file = enc_key_file_opt.unwrap_or(default_enc_key_file);
            // get input and key
            let Ok(input_plaintext) = read_file_as_vec_u8(&input_file) else {
                eyre::bail!("failed reading input file");
            };
            let enc_key = match read_file_as_vec_u8(&enc_key_file) {
                Ok(keyfile_plaintext) => {
                    parse_key(keyfile_plaintext, args.password.clone(), args.keyname)?
                }
                // generate new key
                Err(_) => {
                    println!("could not open keyfile");
                    create_new_keyfile(args.keyname.clone(), args.password.clone(), &enc_key_file)?;
                    let keyfile_text = read_file_as_vec_u8(&enc_key_file)?;
                    let new_enc_key = parse_key(keyfile_text, args.password.clone(), args.keyname)?;
                    println!(
                        "generated new encryption key: {new_enc_key:?} in {}",
                        enc_key_file.display()
                    );
                    new_enc_key
                }
            };
            // encrypt the input file into output file
            let encrypted = encrypt_chacha(&input_plaintext, &enc_key)?;
            let encrypted = BASE64_STANDARD.encode(encrypted);
            save_file(encrypted.into_bytes(), &output_file)?;
        }
        // no input, invalid
        (None, _, _) => println!("please provide input"),
    };
    Ok(())
}

fn menu_selection() -> eyre::Result<()> {
    println!(
        "Please enter the corresponding number to continue:\n\
        1 Add new key\n\
        2 Remove key\n\
        3 Encrypt file using XChaCha20Poly1305\n\
        4 Decrypt file using XChaCha20Poly1305\n\
        5 Encrypt file using AES-256-GCM-SIV\n\
        6 Decrypt file using AES-256-GCM-SIV\n\
        7 Calculate Hash\n\
        8 Exit program"
    );
    //Getting user input
    let answer = get_input_string().expect("error");
    // Creating a Vec with choices needing a password to compare to user input
    let requiring_pw = vec![
        "1".to_string(),
        "2".to_string(),
        "3".to_string(),
        "4".to_string(),
        "5".to_string(),
        "6".to_string(),
    ];
    //check if the operation needs access to the keymap, requiring a password. Hashing can be done without a password.
    if requiring_pw.contains(&answer) {
        //All functions in this if-block require a password
        //Check if there is a key.file in the directory
        let (password, keymap_plaintext, new) = if !Path::new("./key.file").exists() {
            //No key.file found. Ask if a new one should be created.
            create_new_keyfile_interactive().expect("error")
        } else {
            //key.file found. Reading and decrypting content
            read_keyfile_interactive().expect("error")
        };
        match answer.as_str() {
            "1" => {
                if !new {
                    return Ok(());
                }
                add_key(keymap_plaintext, password)
            }
            "2" => remove_key(keymap_plaintext, password),
            "3" => encrypt_file_procedual(keymap_plaintext, "chacha"),
            "4" => decrypt_file_procedual(keymap_plaintext, "chacha"),
            "5" => encrypt_file_procedual(keymap_plaintext, "aes"),
            "6" => decrypt_file_procedual(keymap_plaintext, "aes"),
            _ => Ok(()),
        }
    } else {
        match answer.as_str() {
            "7" => choose_hashing_function(),
            "8" => {
                println!("exiting program");
                exit(0);
            }
            _ => Ok(()),
        }
    }
}
