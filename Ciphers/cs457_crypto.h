
/*
Encrypts the given plaintext using the One-Time Pad cipher.
    @param
        - plaintext: A pointer to the plaintext string.
        - n: The length of the plaintext string.
        - key: A pointer to the encryption key.
    @return a pointer to the encrypted ciphertext.
*/
char *one_time_pad_encr(const char *plaintext, int n, void *key);

/*
Decrypts the given ciphertext using the One-Time Pad cipher.
    @param
        - ciphertext: A pointer to the ciphertext string.
        - n: The length of the ciphertext string.
        - key: A pointer to the decryption key.
    @return a pointer to the decrypted plaintext.
*/
char *one_time_pad_decr(const char *ciphertext, int n, void *key);

/*
Encrypts the given plaintext using the Affine cipher
    @param
        - plaintext: A pointer to the plaintext string.
    @return a pointer to the encrypted ciphertext.

*/
char *affine_encr(const char *plaintext);

/*
Decrypts the given ciphertext using the Affine cipher
    @param
        - ciphertext: A pointer to the ciphertext string.
    @return a pointer to the decrypted plaintext.

*/
char *affine_decr(const char *ciphertext);