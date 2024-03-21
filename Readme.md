# Ciphers and Key-Value Store

A handful of ciphers as well as a implementation of a Key-Value Store using the OpenSSL library for encryption/decryption.

## Table of Contents

- [Dependencies](#dependencies)
- [Usage](#usage)
- [Ciphers](#ciphers)
    - [One-Time Pad](#one-time-pad)
    - [Affine Cipher](#affine-cipher)
    - [Substitution algorithm decryptor](#substitution-algo)
    - [Trithemius Cipher](#trithemius-cipher)
    - [Scytale Cipher](#scytale-cipher)
    - [Rail Fence Cipher](#rail-fence-cipher)
- [Key-Value Store](#key-value-store)
- [Contributing](#contributing)
- [License](#license)

## Dependencies

The following are required in order to compile and run the project:
    - OpenSSL
    - make
    - gcc

## Usage

How to compile the project:
```bash
    make clean
    make
```
> After compiling the project, the following command will run and test the ciphers:
    
    ```bash
    ./ciphers
    ```

> The following command will run and test the key-value store:
> 
> -add operation:
>
>     ```bash
>     ./kv add -f [filename] [key] [value]
>     ```
>
> -read operation:
>
>     ```bash
>     ./kv read -f [filename] [key]
>     ```
>
> -range-read operation:
>
>     ```bash
>     ./kv range-read -f [filename] [key1] [key2]
>     ```
> 
> Please enter the commands **exactly** as specified above to successfully run and test each operation.
> Also, please use the **same** master password for all operations or the decryption **will** fail.

## Ciphers
In the following sections the ciphers implementations are described.

### One-Time Pad
The One-Time Pad cipher is a symmetric encryption algorithm that uses a key of the same length as the message to encrypt it. The key is generated randomly using /dev/urandom and is used only once. The key is XORed with the message to produce the ciphertext.

For the decryption, the same key we used for the encryption is XORed with the ciphertext to produce the original message.

### Affine Cipher
For the encrytion proccess we use the following formula:
    c = (5* p + 8) mod 26
where:
    - c is the ciphertext
    - p is the plaintext
If the letter is lowercase the we also add 26 to the result.
If the char is not a letter the it remains as is.
We also use two helper functions to convert the char to its corresponding number (position) and vice versa.

For the decryption proccess we use the following formula:
    p = 21 * (c - 8 + 26) mod 26
where:
    - c is the ciphertext
    - p is the plaintext
The rest of the process remains the same as in the encryption.

### Substitution algorithm decryptor
In this algorithm we follow these steps:
    - We convert the given ciphertext to string with '*' in the place of the unknown characters.
    - In a while loop:
        - We print the frequencies of the letters in the given ciphertext as well as in the words.txt which is essentially the english dictionary.
        - We ask for the user to input a letter that he wants to change in the ciphertext (mapping).
        - We clear out the buffer of redundant '\n' characters.
        - We ask for the user to input a partially decripted word.
        - We print all the words in the dictionary that match the given pattern.
        - Lastly, we check if the intermediate plaintext contains any '*' characters. If it does, we continue the loop, else we break out of it and thus, we have decripted the string.

The decripted string given for the assignment is: This is a text that has been encrypted using the affine algorithm and given as an assigment in the Computer Science Department of the University of Crete.

**IMPORTANT** : the mapping should be as given exactly in the following form (no extra spaces before,between or after) : x -> y , where y is the letter in the cipher and x the letter tha will replace y.
**EXTRA-IMPORTANT** : if you provide a wrong  mapping, the program will terminate. Also due to the time consuming nature of the algorithm if you do not want to test it, you can comment out the line 54 in the demo.c file.


### Trithemius Cipher
The encryption process works in the following way:
For each character that is a letter we use the tabula_recta and the var last to get to the correct row in the tabula recta. We also use the get_pos helper function to get the position of the letter in the alphabet. 
The var last is needed because we need to know the last letter that was used in the tabula recta so that we can get to the correct row.

For the decryption process:
We follow the same process but now in order to find the column we use the last var and go backwards (subtract). If we reach a negative number we add 26 to it.

### Scytale Cipher
The encryption process works in the following way:
We use the given key to determine the number of columns that the plaintext will be written in the scytale. Then we write the plaintext in the scytale and then we read it in a column by column manner.

For the decryption process:
We follow the same process but now we use the key to determine the number of rows that the plaintext will be written in the scytale. Then we write the plaintext in the scytale and then we read it in a row by row manner.

### Rail Fence Cipher
The encryption process works in the following way:
We use the given key to determine the number of rows that the plaintext will be written in the rail fence. Then we write the plaintext in the rail fence in a zig-zag pattern. The ciphertext is then read in a row by row manner.

For the decryption proccess:
We follow the same process but now we use the key to determine the number of columns that the plaintext will be written in the rail fence. Then we write the plaintext in the rail fence in a zig-zag pattern. The ciphertext is then read in a zig-zag pattern.

## Key-Value Store
The key-value store is implemented using the OpenSSL library for encryption/decryption. The key-value store is implemented in the kv.c file. The key-value store supports the following operations:
    - add
    - read
    - range-read
We use the EVP_Bytes_to_Key() to derive the key and iv which will be used for the encryption / decryption. We use the EVP_aes_256_cbc() for the encryption / decryption process. We also use the EVP_EncryptUpdate() and EVP_DecryptUpdate() to encrypt / decrypt the data. We also use the EVP_EncryptFinal_ex() and EVP_DecryptFinal_ex() to finalize the encryption / decryption process. We also use the EVP_CIPHER_CTX_free() to free the memory that was allocated for the encryption / decryption process.


**IMPORTANT** : the master password should be the same for all operations or the decryption will fail. Additionally, we write the encrypted values in hex format so that we avoid terminating chars which will cause problems in the reading process. Also, the key,value pairs are encrypted together and placed in the file. Then they are also decripted together and using strtok, we separate the key and the value.

## Authors
This project was made me, Alexandros Fourtounis / csd5031.

## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

## License

[MIT](https://choosealicense.com/licenses/mit/)