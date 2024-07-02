# enc_file (Modded from LazyEmpiricist's)

Encrypt / decrypt files or calculate the HASH from the command line. Written in safe Rust

Encryption:

- XChaCha20Poly1305 (https://docs.rs/chacha20poly1305)

Encoding:

- bincode (https://docs.rs/bincode) for encoding

Hashing:

- BLAKE3 (https://docs.rs/blake3)
- SHA2-256 / SHA2-512 (https://docs.rs/sha2)
- SHA3-256 / SHA3-512 (https://docs.rs/sha3)

## Usage in direct mode

##### Store wallet private key in a file

make a file `hyper.key` to store the ETH wallet private key for encryption

```
nano hyper.key
```

run with input file, enc, and password parameters

```
chacha_poly_cli --input hyper.key --enc key.file
Please enter the password
password
```

(for first) run it will generate a key.file and print the encryption key

```
could not open key.file
generated new encryption key: "aiERpT0nehFdxH9n0ZXC0QTpkuY5KFXc" in key.file
```

it will generate `hyper.key.crpt` which has the encrypted material

##### More details

```
chacha-poly-cli -h
```

### Details

package name: chacha-poly
lib name: chacha-poly
bin name: chacha-poly-cli