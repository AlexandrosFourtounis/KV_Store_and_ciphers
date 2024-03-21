#include <stdio.h>
#include <openssl/evp.h>
#include <string.h>
#include "sort_keys.h"

int main(int argc, char *argv[])
{
    if (!argv || argc < 3)
    {
        printf("Wrong Iput.\nUsage: %s <operation(add,read,range-read)> -f <filename> <add?(key value)|read?(key)|range-read?(key1,key2)>\n", argv[0]);
        return 1;
    }
    const char *operation = argv[1];
    const char *filename = argv[3];
    int value = 0;
    int key1 = 0;
    char password[100];
    printf("Enter password: ");
    scanf("%s", password);
    unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
    if (EVP_BytesToKey(EVP_aes_128_cbc(), EVP_md5(), NULL, (unsigned char *)password, strlen(password), 1, key, iv) == 0)
    {
        printf("Error generating key and IV\n");
        return 1;
    }
    if (strcmp(operation, "add") == 0)
    {
        key1 = atoi(argv[4]);
        value = atoi(argv[5]);
        EVP_CIPHER_CTX *ctx = NULL;
        ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
        {
            printf("Error creating context\n");
            return 1;
        }

        int out_len = 0;
        /*open file with append mode*/
        FILE *db = fopen("db.txt", "a");
        if (db == NULL)
        {
            printf("Error opening file\n");
            return 1;
        }
        /*copy the 2 values to be encrypted to a single string*/
        char kv_str[40];
        sprintf(kv_str, "%d,%d", key1, value);
        /*initialize the encryption with the generated key and iv*/
        if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1)
        {
            printf("Error initializing encryption\n");
            return 1;
        }
        /*+1 is needed for the '\0' char*/
        int kv_length = strlen(kv_str) + 1;
        /*+16 is needed for the padding*/
        unsigned char *kv_out = (unsigned char *)malloc(kv_length + 16);
        /*feed the input to the cipher*/
        if (EVP_EncryptUpdate(ctx, kv_out, &out_len, (unsigned char *)kv_str, kv_length) != 1)
        {
            printf("Error encrypting key-value pair\n");
            return 1;
        }
        int kv_out_len = out_len;
        if (EVP_EncryptFinal_ex(ctx, kv_out + out_len, &out_len) != 1)
        {
            printf("Error finalizing encryption\n");
            return 1;
        }
        kv_out_len += out_len;
        /*cleanup for reuse of same context -> redundant from latest commit*/
        EVP_CIPHER_CTX_cleanup(ctx);

        /*convert to hexadecimal string to avoid terminating chars and store it in the db.txt file*/
        char *hex_out = (char *)malloc(kv_out_len * 2 + 1);
        for (int i = 0; i < kv_out_len; i++)
        {
            sprintf(hex_out + i * 2, "%02x", kv_out[i]);
        }
        hex_out[kv_out_len * 2] = '\0';
        /*copy the hex encrypted string to the file, then close and free the memory*/
        fprintf(db, "%s\n", hex_out);
        fclose(db);
        EVP_CIPHER_CTX_free(ctx);
        printf("DEBUG: key-value pair was encrypted and appended\n");
    }
    else if (strcmp(operation, "read") == 0)
    {
        key1 = atoi(argv[4]);
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        /*open file for reading*/
        FILE *db = fopen("db.txt", "r");
        if (!db)
        {
            printf("Error opening file\n");
            return 1;
        }
        char line[256];
        /*while loop for each line read*/
        while (fgets(line, sizeof(line), db))
        {
            line[strcspn(line, "\n")] = '\0';
            // Convert line back to binary
            int line_len = strlen(line);
            unsigned char *line_bin = (unsigned char *)malloc(line_len / 2);
            for (int i = 0; i < line_len; i += 2)
            {
                sscanf(line + i, "%2hhx", &line_bin[i / 2]);
            }
            line_len /= 2;
            int out_len, final_len;
            final_len = 0;
            /*+16 is needed for the padding*/
            unsigned char *line_out = malloc(line_len + 16);
            /*feed the key and iv and initialize the context*/
            if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1)
            {
                printf("Error initializing decryption context\n");
                return 1;
            }
            if (EVP_DecryptUpdate(ctx, line_out, &out_len, line_bin, line_len) != 1)
            {
                printf("Error decrypting line\n");
                return 1;
            }
            out_len += final_len;
            if (EVP_DecryptFinal_ex(ctx, line_out + out_len, &final_len) != 1)
            {
                printf("Error finalizing decryption, you may have entered wrong master password\n");
                ERR_print_errors_fp(stderr); // print errors to stderr
                return 1;
            }
            out_len += final_len;
            line_out[out_len] = '\0';
            EVP_CIPHER_CTX_cleanup(ctx);
            /*divide back to 2 strings using strtok*/
            char *key_str = strtok((char *)line_out, ",");
            char *value_str = strtok(NULL, ",");
            if (!key_str || !value_str)
            {
                printf("Error parsing line\n");
                return 1;
            }
            /*check if it matches the key the user wants*/
            if (atoi(key_str) == key1)
            {
                printf("Key: %s, Value: %s\n", key_str, value_str);
                free(line_bin);
                free(line_out);
                return 0;
            }
            free(line_bin);
            free(line_out);
        }
        free(ctx);
        fclose(db);
    }
    else if (strcmp(operation, "range-read") == 0)
    {
        key1 = atoi(argv[4]);
        int key2 = atoi(argv[5]);
        if(key1 <=0 || key2 <=0){
            printf("Error: key1 and key2 must be positive integers\n");
            return 1;
        }
        /*open file for reading*/
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        FILE *db = fopen("db.txt", "r");
        if (!db)
        {
            printf("Error opening file\n");
            return 1;
        }
        char line[256];
        int **found_kv;
        found_kv = (int **)malloc(1024 * sizeof(int *));
        for (int i = 0; i < 1024; i++)
        {
            found_kv[i] = (int *)malloc(2 * sizeof(int));
        }
        int c = 0;
        int n;
        /*while loop for each line read*/
        while (fgets(line, sizeof(line), db))
        {
            /*remove the '\n' char at the end and insert the '\0'*/
            line[strlen(line)] = '\0';
            // Convert line back to binary
            int line_len = strlen(line);
            unsigned char *line_bin = (unsigned char *)malloc(line_len / 2);
            for (int i = 0; i < line_len; i += 2)
            {
                sscanf(line + i, "%2hhx", &line_bin[i / 2]);
            }
            line_len /= 2;
            int out_len, final_len;
            final_len = 0;
            /*+16 is needed for padding*/
            unsigned char *line_out = malloc(line_len + 16);
            /*initialize the context and feed the key and iv*/
            if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1)
            {
                printf("Error initializing decryption context\n");
                return 1;
            }
            if (EVP_DecryptUpdate(ctx, line_out, &out_len, line_bin, line_len) != 1)
            {
                printf("Error decrypting line\n");
                return 1;
            }
            out_len += final_len;
            if (EVP_DecryptFinal_ex(ctx, line_out + out_len, &final_len) != 1)
            {
                printf("Error finalizing decryption, you may have entered wrong master password\n");
                ERR_print_errors_fp(stderr);
                return 1;
            }
            out_len += final_len;
            line_out[out_len] = '\0';
            /*cleanup context for future use*/
            EVP_CIPHER_CTX_cleanup(ctx);
            // printf("Decrypted line: %s\n", line_out);

            /*divide the decrypted line back to 2 strings*/
            char *key_str = strtok((char *)line_out, ",");
            char *value_str = strtok(NULL, ",");
            if (!key_str || !value_str)
            {
                printf("Error dividing line\n");
                return 1;
            }
          
            /*check if the key is in the range of the provided keys*/
            if (atoi(key_str) >= key1 && atoi(key_str) <= key2)
            {
                int key = atoi(key_str);
                found_kv[c][0] = key;
                key=atoi(value_str);
                found_kv[c][1] = key;
                c++;
            }
         
            free(line_bin);
            free(line_out);
        }
 
        int **sorted_kv = sort_keys(found_kv, c);

        int i = 0;
        if (!found_kv || !sorted_kv)
        {
            printf("Error sorting keys\n");
            return 1;
        }
        while (sorted_kv[i][0] != NULL)
        {
            printf("Key: %d, Value: %d\n", sorted_kv[i][0], sorted_kv[i][1]);
            free(sorted_kv[i]);
            i++;
        }
        free(sorted_kv);
        printf("DEBUG: range-read was entered\n");
        free(ctx);
        fclose(db);
    }
    else
    {
        printf("ERROR: Unknown operation '%s'\n", operation);
    }

    return 0;
}