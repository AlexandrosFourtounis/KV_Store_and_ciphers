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
    char *key = "randombyte"; // Allocate memory for the key
                              // Generate a random key of length 9

    char *plaintext = "ThisIsACat";

    char *ciphertext = one_time_pad_encr(plaintext, 10, key);
    char *decrypted = one_time_pad_decr(ciphertext, 10, key);
    printf("Plaintext: %s\n", plaintext);
    for (int i = 0; i < strlen(ciphertext); i++)
    {
        printf("Ciphertext[%d]: 0x%02x\n", i, ciphertext[i]);
    }
    printf("Decrypted: %s\n", decrypted);

    return 0;
}