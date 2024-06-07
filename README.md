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
##### Generate the 
start the program
```
chacha-poly-cli
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