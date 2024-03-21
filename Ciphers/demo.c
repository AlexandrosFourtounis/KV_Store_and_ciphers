#include "cs457_crypto.h"
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

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
    /*One-time-pad demo*/
    char *one_time_pad_plaintext = "ThisIsACat";
    char *one_time_pad_key = malloc(strlen(one_time_pad_plaintext) * sizeof(char));
    generate_key(one_time_pad_key, strlen(one_time_pad_plaintext));
    char *one_time_pad_ciphertext = one_time_pad_encr(one_time_pad_plaintext, strlen(one_time_pad_plaintext), one_time_pad_key);
    char *one_time_pad_decrypted = one_time_pad_decr(one_time_pad_ciphertext, strlen(one_time_pad_plaintext), one_time_pad_key);
    printf("\n One-time-pad demo: \n given plaintext: %s \n ciphertext: %s \n decrypted plaintext: %s \n", one_time_pad_plaintext, one_time_pad_ciphertext, one_time_pad_decrypted);

    /*affine cipher demo*/
    char *affine_plaintext = "AFFINECIPHER";
    char *affine_ciphertext = affine_encr(affine_plaintext);
    char *affine_decrypted = affine_decr(affine_ciphertext);
    printf("Affine cipher demo: \n");
    printf("Given plaintext: %s \n", affine_plaintext);
    printf("Affine Ciphertext: %s\n", affine_ciphertext);
    printf("Affine Decrypted: %s\n", affine_decrypted);

    /*substitution algorithm decryptor demo*/
    char *substitution_algo_dec_plain = "Pfim im k pwbp pfkp fkm nwwx wxqjedpwt smixc pfw kzzixw krcajipfu kxt civwx km kx kmmicuwxp ix pfw Qaudspwj Mqiwxqw Twdkjpuwxp az pfw Sxivwjmipe az Qjwpw.";

    /*
    IMPORTANT!!
    To test the substitution algorithm decryptor uncomment the following line.
    Due to its time consuming nature it is left commented.
    */
    //char *substitution_dec = substitution_decr(substitution_algo_dec_plain);
    printf("IMPORTANT!! In order to test the substitution algorithm decryptor, uncomment the line 54.\n");
    printf("It is left commented due to the time consuming nature of the algorithm.\n");

    /*trithemius cipher demo*/
    char *trithemius_plaintext = "HELLO";
    char *trithemius_ciphertext = trithemius_encr(trithemius_plaintext);
    char *trithemius_decrypted = trithemius_decr(trithemius_ciphertext);
    printf("Trithemius cipher demo: \n");
    printf("Given plaintext: %s \n", trithemius_plaintext);
    printf("Trithemius Ciphertext: %s\n", trithemius_ciphertext);
    printf("Trithemius Decrypted: %s\n", trithemius_decrypted);

    /*scytale cipher demo*/
    char *scytale_plaintext = "I am hurt very badly help";
    char *scytale_ciphertext = scytale_encr(scytale_plaintext, 5);
    char *scytale_decrypted = scytale_decr(scytale_ciphertext, 5);
    printf("Scytale cipher demo:\n");
    printf("Given plaintext: %s\n", scytale_plaintext);
    printf("Scytale Ciphertext: %s\n", scytale_ciphertext);
    printf("Scytale Decrypted: %s\n", scytale_decrypted);

    /*rail-fence cipher demo*/
    char *rail_fence_plaintext = "WEAREDISCOVEREDRUNATONCE";
    char *rail_fence_ciphertext = rail_fence_encr(rail_fence_plaintext, 3);
   // char *rail_fence_decrypted = rail_fence_decr(rail_fence_ciphertext, 3);
    printf("Rail-fence cipher demo: \n");
    printf("Given plaintext: %s \n", rail_fence_plaintext);
    printf("Rail-fence Ciphertext: %s\n", rail_fence_ciphertext);
    //printf("Rail-fence Decrypted: %s\n", rail_fence_decrypted);

}
