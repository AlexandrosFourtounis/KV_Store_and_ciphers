#include "cs457_crypto.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

char letters[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
char tabula_recta[26][26] = {
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "BCDEFGHIJKLMNOPQRSTUVWXYZA",
    "CDEFGHIJKLMNOPQRSTUVWXYZAB",
    "DEFGHIJKLMNOPQRSTUVWXYZABC",
    "EFGHIJKLMNOPQRSTUVWXYZABCD",
    "FGHIJKLMNOPQRSTUVWXYZABCDE",
    "GHIJKLMNOPQRSTUVWXYZABCDEF",
    "HIJKLMNOPQRSTUVWXYZABCDEFG",
    "IJKLMNOPQRSTUVWXYZABCDEFGH",
    "JKLMNOPQRSTUVWXYZABCDEFGHI",
    "KLMNOPQRSTUVWXYZABCDEFGHIJ",
    "LMNOPQRSTUVWXYZABCDEFGHIJK",
    "MNOPQRSTUVWXYZABCDEFGHIJKL",
    "NOPQRSTUVWXYZABCDEFGHIJKLM",
    "OPQRSTUVWXYZABCDEFGHIJKLMN",
    "PQRSTUVWXYZABCDEFGHIJKLMNO",
    "QRSTUVWXYZABCDEFGHIJKLMNOP",
    "RSTUVWXYZABCDEFGHIJKLMNOPQ",
    "STUVWXYZABCDEFGHIJKLMNOPQR",
    "TUVWXYZABCDEFGHIJKLMNOPQRS",
    "UVWXYZABCDEFGHIJKLMNOPQRST",
    "VWXYZABCDEFGHIJKLMNOPQRSTU",
    "WXYZABCDEFGHIJKLMNOPQRSTUV",
    "XYZABCDEFGHIJKLMNOPQRSTUVW",
    "YZABCDEFGHIJKLMNOPQRSTUVWX",
    "ZABCDEFGHIJKLMNOPQRSTUVWXY"};

char *one_time_pad_encr(const char *plaintext, int n, void *key)
{
    char *ciphertext = (char *)malloc(n + 1);
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
    char *plaintext = (char *)malloc(n + 1);
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
    while (letters[i] != '\0')
    {
        if (letters[i] == c)
        {
            printf("DEBUG: char %c has pos %d\n", c, i);
            return i;
        }
        i++;
    }
    fprintf(stderr, "undefined char provided");
    return -1;
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
        else if (plaintext[i] >= 'A' && plaintext[i] <= 'Z')
        {
            int pos = get_pos(plaintext[i]);
            ciphertext[i] = get_char_from_pos((5 * pos + 8) % 26);
        }
        else if (plaintext[i] >= 'a' && plaintext[i] <= 'z')
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
        else if (ciphertext[i] >= 'A' && ciphertext[i] <= 'Z')
        {
            int pos = get_pos(ciphertext[i]);
            plaintext[i] = get_char_from_pos((21 * (pos - 8 + 26)) % 26);
        }
        else if (ciphertext[i] >= 'a' && ciphertext[i] <= 'z')
        {
            int pos = get_pos(ciphertext[i]);
            plaintext[i] = get_char_from_pos((21 * (pos - 8 + 26)) % 26);
        }
        i++;
    }
    plaintext[i] = '\0';
    return plaintext;
}

char *trithemius_encr(const char *plaintext)
{
    int i, last, j = 0;
    int len = strlen(plaintext);
    char *ciphertext = malloc(len + 1);
    if (!ciphertext)
    {
        return NULL;
    }
    while (plaintext[j] != '\0')
    {
        if(j == len){
            j = 0;
        }
        if (plaintext[j] >= 'A' && plaintext[j] <= 'Z')
        {
            if (last != 0)
            {
                i = get_pos(plaintext[j]);
                ciphertext[j] = tabula_recta[j % 26][i];
            }
            else
            {
                i = get_pos(plaintext[last]);
                ciphertext[last] = tabula_recta[(last) % 26][i];
            }
        }
        else if (plaintext[j] >= 'a' && plaintext[j] <= 'z')
        {
            if (last != 0)
            {
                i = get_pos(toupper(plaintext[j]));
                ciphertext[j] = tolower(tabula_recta[j % 26][i]);
            }
            else
            {
                i = get_pos(toupper(plaintext[last]));
                ciphertext[last] = tolower(tabula_recta[(last) % 26][i]);
            }
        }
        else
        {
            last = j;
            ciphertext[j] = plaintext[j];
        }
        j++;
    }
    ciphertext[j] = '\0';
    return ciphertext;
}

char *trithemius_decr(const char *ciphertext)
{
    char *plaintext = malloc(strlen(ciphertext) + 1);
    if (!plaintext)
    {
        return NULL;
    }
    int i, j = 0;

}

char *rail_fence_encr(const char *plaintext, int key)
{
    int len = strlen(plaintext);
    char *ciphertext = malloc(len + 1);
    if (!ciphertext)
    {
        return NULL;
    }

    int rail_len = 2 * key - 2;
    int rail_num = len / rail_len + 1;
    int rail_pos = 0;

    for (int i = 0; i < key; i++)
    {
        for (int j = i; j < len; j += rail_len)
        {
            ciphertext[rail_pos++] = plaintext[j];
            if (i != 0 && i != key - 1 && j + rail_len - 2 * i < len)
            {
                ciphertext[rail_pos++] = plaintext[j + rail_len - 2 * i];
            }
        }
    }
    ciphertext[len] = '\0';
    return ciphertext;
}

char *rail_fence_decr(const char *ciphertext, int key)
{
    int len = strlen(ciphertext);
    char *plaintext = malloc(len + 1);
    if (!plaintext)
    {
        return NULL;
    }

    int i = 0;
    int j = 0;
    while (i < key)
    {
        j = i;
        while (j < len)
        {
            plaintext[i] = ciphertext[j];
            j += key;
        }
        i++;
    }
    plaintext[len] = '\0';
    return plaintext;
}