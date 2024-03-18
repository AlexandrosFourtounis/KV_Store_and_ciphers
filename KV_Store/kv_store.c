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
    unsigned char key[16], iv[16];
    if (EVP_BytesToKey(EVP_aes_128_cbc(), EVP_md5(), NULL, password, strlen(password), 2, key, iv) == 0)
    {
        printf("Error generating key and IV\n");
        return 1;
    }

    EVP_CIPHER_CTX *ctx = NULL;
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        printf("Error creating context\n");
        return 1;
    }

    if (strcmp(operation, "add") == 0)
    {
        key1 = atoi(argv[4]);
        value = atoi(argv[5]);
        printf("key = %d, value = %d\n", key1, value);
        unsigned char key_out[128];
        int key_len;
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
        if (EVP_EncryptUpdate(ctx, key_out, &key_len, (unsigned char *)key_str, strlen(key_str)) != 1)
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

        unsigned char value_out[128];
        int value_len;
        char value_str[20];
        sprintf(value_str, "%d", value);
        if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1)
        {
            printf("Error initializing encryption\n");
            return 1;
        }
        if (EVP_EncryptUpdate(ctx, value_out, &value_len, (unsigned char *)value_str, strlen(value_str)) != 1)
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

        fprintf(db, "%s , %s\n", key_out, value_out);
        fclose(db);
        EVP_CIPHER_CTX_free(ctx);
        printf("DEBUG: key and value was encrypted and appended\n");
    }
    else if (strcmp(operation, "read") == 0)
    {
        // TODO: Read file, decrypt key-value pairs, print value for matching key
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