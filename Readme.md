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
        -add operation:
        ```bash
        ./kv add -f [filename] [key] [value]
        ```
        -read operation:
        ```bash
        ./kv read -f [filename] [key]
        ```
        -range-read operation:
        ```bash
        ./kv range-read -f [filename] [key1] [key2]
        ```
    Please enter the commands ==exactly== as specified above to succesfully run and test each operation.

## Contributing

Information about how others can contribute to your project.

## License

Information about the license.