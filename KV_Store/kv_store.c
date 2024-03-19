#include <stdio.h>
#include <openssl/evp.h>
#include <string.h>

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
    printf("key is %s\n iv is %s\n", key, iv);
    if (strcmp(operation, "add") == 0)
    {
        key1 = atoi(argv[4]);
        value = atoi(argv[5]);
        printf("key = %d, value = %d\n", key1, value);
        EVP_CIPHER_CTX *ctx = NULL;
        ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
        {
            printf("Error creating context\n");
            return 1;
        }

        int key_len = 0;
        FILE *db = fopen("db.txt", "a");
        if (db == NULL)
        {
            printf("Error opening file\n");
            return 1;
        }
        char key_str[20];
        sprintf(key_str, "%d", key);
        if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1)
        {
            printf("Error initializing encryption\n");
            return 1;
        }
        int key_length = strlen(key_str) + 1;
        unsigned char *key_out = (unsigned char *)malloc(key_length + 16);
        if (EVP_EncryptUpdate(ctx, key_out, &key_len, (unsigned char *)key_str, key_length) != 1)
        {
            printf("Error encrypting key\n");
            return 1;
        }
        int key_out_len = key_len;
        if (EVP_EncryptFinal_ex(ctx, key_out + key_len, &key_len) != 1)
        {
            printf("Error finalizing encryption\n");
            return 1;
        }
        key_out_len += key_len;
        EVP_CIPHER_CTX_cleanup(ctx);

        int value_len = 0;
        char value_str[20];
        sprintf(value_str, "%d", value);
        int value_length = strlen(value_str) + 1;
        printf("length of value_str = %d\n", value_length);
        unsigned char *value_out = (unsigned char *)malloc(value_length + 16);
        if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1)
        {
            printf("Error initializing encryption\n");
            return 1;
        }
        if (EVP_EncryptUpdate(ctx, value_out, &value_len, (unsigned char *)value_str, value_length) != 1)
        {
            printf("Error encrypting key\n");
            return 1;
        }
        int value_out_len = value_len;
        if (EVP_EncryptFinal_ex(ctx, value_out + value_len, &value_len) != 1)
        {
            printf("Error finalizing encryption\n");
            return 1;
        }
        value_out_len += value_len;
        EVP_CIPHER_CTX_cleanup(ctx);

        fwrite(key_out, 1, key_out_len, db);
        fprintf(db, ",");
        fwrite(value_out, 1, value_out_len, db);
        fprintf(db, "\n");
        fclose(db);
        EVP_CIPHER_CTX_free(ctx);
        printf("DEBUG: key and value was encrypted and appended\n");
    }
    else if (strcmp(operation, "read") == 0)
    {
        key1 = atoi(argv[4]);
        char key1_str[20];
        sprintf(key1_str, "%d", value);

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

        FILE *db = fopen("db.txt", "r");
        if (!db)
        {
            printf("Error opening file\n");
            return 1;
        }
        char line[256];
        while (fgets(line, sizeof(line), db))
        {
            line[strcspn(line, "\n")] = '\0';
            printf("DEBUG line: %s\n", line);
            char *key_str = strtok(line, ",");
            char *value_str = strtok(NULL, ",");
            int key_len, value_len, out_len, final_len;
            unsigned char *key_out = malloc(EVP_MAX_BLOCK_LENGTH);
            unsigned char *value_out = (unsigned char *)malloc(strlen(value_str) + 1);
            // unsigned char key_out[EVP_MAX_BLOCK_LENGTH+1024];
            key_len = 0;
            if (!key_str || !value_str)
            {
                printf("Error parsing line\n");
                return 1;
            }

            printf("DEBUG: key_str = %s, value_str = %s\n", key_str, value_str);

            if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1)
            {
                printf("Error initializing decryption context\n");
                return 1;

            }
            //EVP_CIPHER_CTX_set_padding(ctx, 0);
            if (EVP_DecryptUpdate(ctx, key_out, &key_len, (unsigned char *)key_str, strlen(key_str)) != 1)
            {
                printf("Error decrypting key\n");
                return 1;
            }
            out_len = key_len;
            if (EVP_DecryptFinal_ex(ctx, key_out + key_len, &final_len) != 1)
            {
                printf("Error finalizing key decryption\n");
                ERR_print_errors_fp(stderr);
                return 1;
            }
            out_len += final_len;
            key_out[out_len] = '\0';
            EVP_CIPHER_CTX_cleanup(ctx);
            printf("Key: %s, Value:\n", key_out);

            if (strcmp((char *)key_out, key_str) == 0)
            {
                printf("SUCCESS Key: %s, Value: \n", (char *)key_str);
            }

            EVP_CIPHER_CTX_free(ctx);
        }

        fclose(db);

        printf("DEBUG: read was entered\n");
    }
    else if (strcmp(operation, "range-read") == 0)
    {
        // TODO: Read file, decrypt key-value pairs, print values for keys in range
        printf("DEBUG: range-read was entered\n");
    }
    else
    {
        printf("ERROR: Unknown operation '%s'\n", operation);
    }

    return 0;
}