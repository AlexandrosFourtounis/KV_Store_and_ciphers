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
            // printf("DEBUG: char %c has pos %d\n", c, i);
            return i;
        }
        i++;
    }
    fprintf(stderr, "undefined char provided");
    return -1;
}

char get_char_from_pos(int i)
{
    if (i >= 0 && i < strlen(letters))
    {
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
    int i, last = 0;
    int j = 0;
    int len = strlen(plaintext);
    char *ciphertext = malloc(len + 1);
    if (!ciphertext)
    {
        return NULL;
    }
    while (plaintext[j] != '\0')
    {
        if (plaintext[j] >= 'A' && plaintext[j] <= 'Z')
        {

            i = get_pos(plaintext[j]);
            ciphertext[j] = tabula_recta[last % 26][i];
            last++;
        }
        else if (plaintext[j] >= 'a' && plaintext[j] <= 'z')
        {

            i = get_pos(toupper(plaintext[j]));
            ciphertext[j] = tolower(tabula_recta[last % 26][i]);
            last++;
        }
        else
        {
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
    int last = 0;
    while (ciphertext[j] != '\0')
    {
        if ((ciphertext[j] >= 'A' && ciphertext[j] <= 'Z') || (ciphertext[j] >= 'a' && ciphertext[j] <= 'z'))
        {
            i = 0;
            while (tabula_recta[last % 26][i] != '\0')
            {
                if (tabula_recta[last % 26][i] == ciphertext[j])
                {
                    break;
                }
                i++;
            }

            i -= last % 26;
            if (i < 0)
                i = i + 26;
            plaintext[j] = (ciphertext[j] >= 'A' && ciphertext[j] <= 'Z') ? tabula_recta[last % 26][i] : tolower(tabula_recta[last % 26][i]);
            last++;
            i = 0;
        }
        else
        {
            plaintext[j] = ciphertext[j];
        }
        j++;
    }
    plaintext[j] = '\0';
    return plaintext;
}

char *rail_fence_encr(const char *plaintext, int key)
{
    int len = strlen(plaintext);
    if (len == 0 || key <= 0)
        return NULL;

    char *ciphertext = malloc((len + 1) * sizeof(char));
    if (!ciphertext)
        return NULL;

    char matrix[key][len];
    memset(matrix, 0, sizeof(matrix));

    int up = 0;
    int row = 0;
    int j = 0;

    int i = 0;
    while (i < len)
    {
        matrix[row][j] = plaintext[i];
        j++;

        switch (up)
        {
        case 0:
            row++;
            up = (row == key) ? 1 : up;
            row = (row == key) ? row - 2 : row;
            break;

        case 1:
            row--;
            up = (row == -1) ? 0 : up;
            row = (row == -1) ? row + 2 : row;
            break;
        }
        i++;
    }
    int k = 0;
    i = 0;
    while (i < key)
    {
        int j = 0;
        while (j < len)
        {
            if (matrix[i][j] != 0)
            {
                ciphertext[k] = matrix[i][j];
                k++;
            }
            j++;
        }
        i++;
    }
    ciphertext[k] = '\0';
    return ciphertext;
}

char *rail_fence_decr(const char *ciphertext, int key)
{
}

char *scytale_encr(const char *plaintext, int diameter)
{
    int len = strlen(plaintext);
    char *ciphertext = malloc(len + 1);
    char scytale[diameter][len / diameter + 1];

    if (!ciphertext)
    {
        return NULL;
    }
    int i = 0;
    int j = 0;
    while (plaintext[i] != '\0')
    {
        scytale[i % diameter][i / diameter] = plaintext[i];
        i++;
    }

    i = 0;
    int rows = len / diameter;
    while (i < diameter)
    {
        j = 0;
        while (j < rows)
        {
            ciphertext[i * rows + j] = scytale[i][j];
            j++;
        }
        i++;
    }
    ciphertext[len] = '\0';
    return ciphertext;
}

char *scytale_decr(const char *ciphertext, int diameter)
{

    int len = strlen(ciphertext);
    char *plaintext = malloc(len + 1);
    if (!plaintext)
    {
        return NULL;
    }
    int i = 0;
    int j = 0;
    int k = 0;
    char scytale[(((len + -1) / diameter) + 1)][diameter];
    while (i < diameter)
    {
        int j = 0;
        while (j < (((len + -1) / diameter) + 1))
        {
            if (i * (((len + -1) / diameter) + 1) + j < len)
            {
                scytale[j][i] = ciphertext[i * (((len + -1) / diameter) + 1) + j];
            }
            j++;
        }
        i++;
    }
    i = 0;
    j = 0;
    do
    {
        j = 0;
        do
        {
            if (i * diameter + j < len)
            {
                plaintext[k++] = scytale[i][j];
            }
            j++;
        } while (j < diameter);
        i++;
    } while (i < (((len + -1) / diameter) + 1));

    plaintext[len] = '\0';
    return plaintext;
}

char *omit_punctuation(char *text)
{
    int i = 0;
    int len = strlen(text);
    char *punctuation = malloc(len + 1);
    char *final = malloc(len + 1);
    int j = 0;
    while (text[i] != '\0')
    {
        if (isalpha(text[i]))
        {
            punctuation[i] = 'a';
            final[j] = text[i];
            j++;
        }
        else
        {
            punctuation[i] = text[i];
        }
        i++;
    }
    punctuation[i] = '\0';
    final[j] = '\0';
}

char **match_words(const char *partial_word, int length)
{
    FILE *fp;
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    char **matching_words = malloc(100000 * sizeof(char *));
    int matching_words_count = 0;

    fp = fopen("words.txt", "r");
    if (fp == NULL)
        exit(EXIT_FAILURE);

    printf("DEBUG: partial word is %s\n", partial_word);
    while ((read = getline(&line, &len, fp)) != -1)
    {
        if (strlen(line) - 1 == length)
        {
            if (strncmp(line, partial_word, strlen(partial_word)) == 0)
            {
                matching_words[matching_words_count] = strdup(line);
                matching_words_count++;
            }
        }
    }

    fclose(fp);
    if (line)
        free(line);

    matching_words[matching_words_count] = NULL;
    return matching_words;
}

int *dictionary_frequency()
{
    int *frequency = malloc(26 * sizeof(int));
    for (int i = 0; i < 26; i++)
    {
        frequency[i] = 0;
    }

    FILE *fp = fopen("words.txt", "r");
    if (fp == NULL)
    {
        printf("Failed to open the file.\n");
        return NULL;
    }
    char c;
    while ((c = fgetc(fp)) != EOF)
    {
        if (isalpha(c))
        {
            c = toupper(c);
            int pos = get_pos(c);
            frequency[pos]++;
        }
    }

    fclose(fp);

    return frequency;
}

int *ciphertext_frequency(const char *ciphertext)
{
    int *frequency = malloc(26 * sizeof(int));
    for (int i = 0; i < 26; i++)
    {
        frequency[i] = 0;
    }

    char c;
    int i = 0;
    while (ciphertext[i] != '\0')
    {
        c = ciphertext[i];
        if (isalpha(c))
        {
            c = toupper(c);
            int pos = get_pos(c);
            frequency[pos]++;
        }
        i++;
    }

    return frequency;
}

char *substitution_decr(const char *ciphertext)
{
    int i = 0;
    int len = strlen(ciphertext);
    char *new_ciphertext = malloc(len + 1);
    char *plaintext = malloc(len + 1);

    if (!new_ciphertext || !ciphertext || !plaintext)
    {
        return NULL;
    }

    while (ciphertext[i] != '\0')
    {
        if (ciphertext[i] == ' ')
        {
            plaintext[i] = ciphertext[i];
        }
        else
        {
            plaintext[i] = '*';
        }
        i++;
    }
    plaintext[i] = '\0';

    i = 0;
    int done = 0;
    printf("%s\n", plaintext);
    while (done == 0)
    {

        int *frequency = dictionary_frequency();
        int *cipher_frequency = ciphertext_frequency(ciphertext);
        printf("Letter | Dictionary Frequency | Ciphertext Frequency\n");
        printf("------------------------------------------------------\n");
        int i = 0;
        while (i < 26)
        {
            printf("%6c | %20d | %20d\n", i + 'A', frequency[i], cipher_frequency[i]);
            i++;
        }
        printf("\n Next mapping: ");
        char mapping[7];
        if (scanf(" %6[^->] -> %c", mapping, &mapping[5]) != 2)
        {
            printf("\nInvalid input. Please provide the input exactly like:x -> y \n Exiting program...\n");
            exit(1);
        }
        int c;
        while ((c = getchar()) != '\n' && c != EOF)
            ;

        char x = mapping[0];
        char y = mapping[5];
        printf("DEBUG: x is %c and y is %c\n", x, y);
        i = 0;
        while (plaintext[i] != '\0')
        {
            if (ciphertext[i] == y)
            {
                plaintext[i] = x;
            }
            i++;
        }
        printf("DEBUG: intermediate plaintext is %s\n", plaintext);

        char *partial_word = malloc(100);
        printf("\n Enter partially decripted word: ");
        scanf("%s", partial_word);
        int j = 0;
        int partial_word_length = strlen(partial_word);

        while (partial_word[j] != '\0')
        {
            if (partial_word[j] == '*')
            {
                partial_word[j] = '\0';
                break;
            }
            j++;
        }

        // printf("\n\nDEBUG: partially decripted word after conversion is : \n %s with length %d \n ", partial_word, partial_word_length);
        char **matched_words = match_words(partial_word, partial_word_length);
        j = 0;
        while (matched_words[j] != NULL)
        {
            printf(" %s , ", matched_words[j]);
            j++;
        }

        i = 0;
        int k = 0;
        while (plaintext[i] != '\0')
        {
            if (plaintext[i] == '*')
            {
                k++;
            }
            i++;
        }
        if (k == 0)
        {
            done = 1;
        }
    }
}