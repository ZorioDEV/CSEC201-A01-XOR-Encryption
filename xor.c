#include <stdio.h>
#include <string.h>

void xorEncryptDecrypt(char *message, char *key) {
    int keyLen = strlen(key);
    for (int i = 0; message[i] != '\0'; i++) {
        message[i] ^= key[i % keyLen];
    }
}

int main() {
    char choice[10], message[256], filename[256], key[32];
    printf("Enter 'encrypt' or 'decrypt': ");
    scanf("%s", choice);

    if (strcmp(choice, "encrypt") == 0) {
        printf("Enter the string to encrypt: ");
        fgets(message, sizeof(message), stdin);
        message[strcspn(message, "\n")] = '\0'; // Remove newline character
        printf("Enter filename to save encrypted data: ");
        scanf("%s", filename);
        printf("Enter key: ");
        scanf("%s", key);

        FILE *file = fopen(filename, "w");
        if (file == NULL) {
            perror("Error opening file for writing");
            return 1;
        }

        xorEncryptDecrypt(message, key);
        fprintf(file, "%s", message);
        fclose(file);
    } else if (strcmp(choice, "decrypt") == 0) {
        printf("Enter filename to read encrypted data: ");
        scanf("%s", filename);
        printf("Enter key: ");
        scanf("%s", key);

        FILE *file = fopen(filename, "r");
        if (file == NULL) {
            perror("Error opening file for reading");
            return 1;
        }

        fseek(file, 0, SEEK_END);
        long size = ftell(file);
        fseek(file, 0, SEEK_SET);

        char *encryptedData = malloc(size + 1);
        if (encryptedData == NULL) {
            perror("Error allocating memory for encrypted data");
            fclose(file);
            return 1;
        }

        fread(encryptedData, 1, size, file);
        encryptedData[size] = '\0';
        fclose(file);

        xorEncryptDecrypt(encryptedData, key);
        printf("Decrypted message: %s\n", encryptedData);
        free(encryptedData);
    } else {
        printf("Invalid choice. Please enter 'encrypt' or 'decrypt'.\n");
    }

    return 0;
}