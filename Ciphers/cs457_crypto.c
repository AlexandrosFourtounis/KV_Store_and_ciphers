#include "cs457_crypto.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

char letters[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

char *one_time_pad_encr(const char *plaintext, int n, void *key)
{
    char *ciphertext = (char *)malloc(n);
    int i = 0;
    while(i<n){
        ciphertext[i] = plaintext[i] ^ ((char *)key)[i];
        i++;
    }
    return ciphertext;
}

char *one_time_pad_decr(const char *ciphertext, int n, void *key){
    char *plaintext = (char *)malloc(n);
    int i = 0;
    while(i<n){
        plaintext[i] = ciphertext[i] ^ ((char *)key)[i];
        i++;
    }
    return plaintext;
}