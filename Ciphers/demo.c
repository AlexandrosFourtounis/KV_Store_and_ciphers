#include "cs457_crypto.h"
#include <stdlib.h>
#include <stdio.h>

#include <fcntl.h>
#include <unistd.h>

// Function to generate a random key
void generate_key(char *key, int key_length)
{
    int urandom = open("/dev/urandom", O_RDONLY);
    if (urandom == -1)
    {
        perror("Failed to open /dev/urandom");
        exit(1);
    }

    ssize_t bytes_read = read(urandom, key, key_length);
    if (bytes_read == -1)
    {
        perror("Failed to read from /dev/urandom");
        exit(1);
    }

    close(urandom);
}

int main()
{
    char *key = "randombyte";

    char *plaintext = "Iamhurtverybadlyhelp?";
    char *temp = "WEERA";
    /*
    char *ciphertext = one_time_pad_encr(plaintext, 10, key);
    char *decrypted = one_time_pad_decr(ciphertext, 10, key);
    printf("Plaintext: %s\n", plaintext);
    for (int i = 0; i < strlen(ciphertext); i++)
    {
        printf("Ciphertext[%d]: 0x%02x\n", i, ciphertext[i]);
    }
    printf("Decrypted: %s\n", decrypted);
    */

    /*    char *affine_ciphertext = affine_encr(plaintext);
    char *affine_decrypted = affine_decr(affine_ciphertext);
    printf("Affine Ciphertext: %s\n", affine_ciphertext);
    printf("Affine Decrypted: %s\n", affine_decrypted);
    char *rail_ciphertext = rail_fence_encr(temp, 3);
    char *rail_decrypted = rail_fence_decr(rail_ciphertext, 3);
    printf("Rail Ciphertext: %s\n", rail_ciphertext);
    printf("Rail Decrypted: %s\n", rail_decrypted);
   
    char *trithemius_ciphertext = trithemius_encr(plaintext);
     char *trithemius_decrypted = trithemius_decr(trithemius_ciphertext);
    printf("Trithemius Ciphertext: %s\n", trithemius_ciphertext);

    printf("Trithemius Decrypted: %s\n", trithemius_decrypted);
    */
    char *scytale_ciphertext = scytale_encr(plaintext,5);
    printf("Scytale Ciphertext: %s\n", scytale_ciphertext);
    char *scytale_decrypted = scytale_decr(scytale_ciphertext,5);
    printf("Scytale Decrypted: %s\n", scytale_decrypted);
}
