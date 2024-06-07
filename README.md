# enc_file (Modded from LazyEmpiricist's)

Encrypt / decrypt files or calculate the HASH from the command line. Written in Rust without use of unsafe code. 

Uses XChaCha20Poly1305 (https://docs.rs/chacha20poly1305) or AES-256-GCM-SIV (https://docs.rs/aes-gcm-siv) for encryption/decryption, bincode (https://docs.rs/bincode) for encoding and BLAKE3 (https://docs.rs/blake3), SHA2-256 / SHA2-512 (https://docs.rs/sha2) oder SHA3-256 / SHA3-512 (https://docs.rs/sha3) for hashing.


## Usage:
### Main menu (if started without any command line arguments)
```
Please enter the corresponding number to continue:
1 Add new key
2 Remove key
3 Encrypt file using XChaCha20Poly1305
4 Decrypt file using XChaCha20Poly1305
5 Encrypt file using AES-256-GCM-SIV
6 Decrypt file using AES-256-GCM-SIV
7 Calculate Hash
8 Exit program
```


### Obtain ciphertext and enable trading
#### Generate encrypted private key ciphertext
make a file, `hyper.key`, to store the ETH wallet private key for encryption
```
code ./hyper.key
```
run the enc_file code
```
cargo run
```
- select 1 to create encryption key, it prints the `encryption key` as below
```
Keys found in key.file:
{"YOUR_KEY_NAME_HERE": "YOUR_ENCRYPTION_KEY_HERE"}
```
- select 3 to encrypt the hypper.key content (wallet private key) and get `hyper.key.crpt`, which has the `ciphertext` as the content
- select 8 to exit