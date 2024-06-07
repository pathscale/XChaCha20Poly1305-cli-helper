# enc_file (Modded from LazyEmpiricist's)

Encrypt / decrypt files or calculate the HASH from the command line. Written in safe Rust

Encryption:
- XChaCha20Poly1305 (https://docs.rs/chacha20poly1305)
- AES-256-GCM-SIV (https://docs.rs/aes-gcm-siv)

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
run with input file parameter
```
chacha-poly-cli -i hyper.key
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



## Usage in interactive mode
run without any parameter
```
chacha-poly-cli
```
### Interactive mode main menu
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


### Obtain ciphertext
#### Generate encrypted private key ciphertext
##### Store wallet private key in a file
make a file `hyper.key` to store the ETH wallet private key for encryption
```
nano hyper.key
```
##### Install the debian package
start the program
```
sudo dpkg -i chacha-poly_1.0.0_arm64.deb
```
select 1: create encryption key, it prints the `encryption key` as below
```
Keys found in key.file:
{"YOUR_KEY_NAME_HERE": "YOUR_ENCRYPTION_KEY_HERE"}
```
select 3: encrypt `hyper.key` (wallet private key) and get `hyper.key.crpt` with encrypted material in the content
```
nano hyper.key.crpt 
```
select 8: exit

### Details
package name: chacha-poly
lib name: chacha-poly
bin name: chacha-poly-cli