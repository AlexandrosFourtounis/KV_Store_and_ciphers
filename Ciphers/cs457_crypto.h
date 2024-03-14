
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

/*
Encrypts the given plaintext using the Trithemian cipher
    @param
        - plaintext: a pointer to the plaintext string.
    @return a pointer to the encrypted ciphertext.
*/
char *trithemius_encr(const char *plaintext);

/*Decrypts the given ciphertext using the Trithemian cipher
    @param
        - ciphertext : a pointer to the ciphertext string.
    @ return a pointer to the encrypted plaintext.*
*/
char *trithemius_decr(const char *ciphertext);

/*Decrypts the given ciphertext using the Rail-Fence cipher
    @param
        - ciphertext : a pointer to the ciphertext string.
        - key : the number of rails.
    @ return a pointer to the encrypted plaintext.*
*/
char *rail_fence_decr(const char *ciphertext, int key);

/*Encrypts the given plaintext using the Rail-Fence cipher
    @param
        - ciphertext : a pointer to the ciphertext string.
    @ return a pointer to the encrypted ciphertext.*
*/
char *rail_fence_encr(const char *plaintext);

