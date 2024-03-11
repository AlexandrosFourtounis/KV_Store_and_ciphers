#include "cs457_crypto.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


char letters[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
char tabula_recta[26][26]


char *one_time_pad_encr(const char *plaintext, int n, void *key)
{
    char *ciphertext = (char *)malloc(n+1);
    int i = 0;
    while (i < n)
    {
        if (plaintext[i] != ' ')
        {
            ciphertext[i] = plaintext[i] ^ ((char *)key)[i];
        }
        else
        {
            ciphertext[i] = plaintext[i];
        }
        i++;
    }
    ciphertext[i] = '\0';
    return ciphertext;
}

char *one_time_pad_decr(const char *ciphertext, int n, void *key)
{
    char *plaintext = (char *)malloc(n+1);
    int i = 0;
    while (i < n)
    {
        if (ciphertext[i] != ' ')
        {
            plaintext[i] = ciphertext[i] ^ ((char *)key)[i];
        }
        else
        {
            plaintext[i] = ciphertext[i];
        }
        i++;
    }
    plaintext[i] = '\0';
    return plaintext;
}

int get_pos(char c)
{
    int i = 0;
    while (letters[i] != '\0') // Add termination condition
    {
        if (letters[i] == c)
        {
            printf("DEBUG: char %c has pos %d\n", c, i);
            return i;
        }
        i++;
    }
    fprintf(stderr, "undefined char provided");
    return -1; // Return -1 if character is not found
}

char get_char_from_pos(int i)
{
    printf("DEBUG: i is %d\n", i);
    if (i >= 0 && i < strlen(letters))
    {
        printf("DEBUG: char %c has value %d\n", letters[i], i);
        return letters[i];
    }
    fprintf(stderr, "undefined position provided");
    return '\0'; 
}

char *affine_encr(const char *plaintext)
{
    int len = strlen(plaintext);
    char *ciphertext = malloc(len + 1); 
    if (!ciphertext)
    {
        return NULL; 
    }

    int i = 0;
    while (plaintext[i] != '\0') 
    {
        if (plaintext[i] == ' ')
        {
            ciphertext[i] = plaintext[i];
        }
        else if(plaintext[i] >= 'A' && plaintext[i] <= 'Z')
        {
            int pos = get_pos(plaintext[i]);
            ciphertext[i] = get_char_from_pos((5 * pos + 8) % 26);
        }else if(plaintext[i] >= 'a' && plaintext[i] <= 'z')
        {
            int pos = get_pos(plaintext[i]);
            ciphertext[i] = get_char_from_pos((5 * pos + 8) % 26 + 26);
        }
        i++;
    }
    ciphertext[i] = '\0'; 
    return ciphertext;
}

char *affine_decr(const char *ciphertext)
{
    int len = strlen(ciphertext);
    char *plaintext = malloc(len + 1);
    if (!plaintext)
    {
        return NULL; 
    }

    int i = 0;
    while (ciphertext[i] != '\0') 
    {
        if (ciphertext[i] == ' ')
        {
            plaintext[i] = ciphertext[i];
        }
        else if(ciphertext[i] >= 'A' && ciphertext[i] <= 'Z')
        {
            int pos = get_pos(ciphertext[i]);
            plaintext[i] = get_char_from_pos((21 * (pos - 8 + 26)) % 26);
        }else if(ciphertext[i] >= 'a' && ciphertext[i] <= 'z')
        {
            int pos = get_pos(ciphertext[i]);
            plaintext[i] = get_char_from_pos((21 * (pos - 8 + 26)) % 26 );
        }
        i++;
    }
    plaintext[i] = '\0'; 
    return plaintext;
}

char *trithemius_encr(const char *plaintext){

}

char *trithemius_decr(const char *ciphertext)
{
}