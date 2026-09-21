#include <stdio.h>
#include <string.h>
#include <stdlib.h>

//changed to take exact length
void xorEncryptDecrypt(char* message, int length, char* key) {
    int keyLen = strlen(key);
    for (int i = 0; i < length; i++) {
        message[i] ^= key[i % keyLen];
    }
}

int main() {
    char choice[10], message[256], filename[256], key[32];

    printf("Enter 'encrypt' or 'decrypt': ");
    fgets(choice, sizeof(choice), stdin);   //swapped from scanf() to fgets() 
    choice[strcspn(choice, "\n")] = '\0';

    if (strcmp(choice, "encrypt") == 0) {
        printf("Enter the string to encrypt: ");
        fgets(message, sizeof(message), stdin);
        message[strcspn(message, "\n")] = '\0'; // Remove newline character

        int length = strlen(message);   //gets exact length

        printf("Enter filename to save encrypted data: ");
        scanf("%s", filename);

        printf("Enter key: ");
        scanf("%s", key);

        FILE* file = fopen(filename, "w");
        if (file == NULL) {
            perror("Error opening file for writing");
            return 1;
        }

        xorEncryptDecrypt(message, length, key);

        fwrite(message, 1, length, file);
        fclose(file);

        //completion message
        printf("%d bytes were written to %s\n", length, filename);
        printf("Encryption is completed!\n");
    }
    else if (strcmp(choice, "decrypt") == 0) {
        printf("Enter filename to read encrypted data: ");
        scanf("%s", filename);
        printf("Enter key: ");
        scanf("%s", key);

        FILE* file = fopen(filename, "r");
        if (file == NULL) {
            perror("Error opening file for reading");
            return 1;
        }

        fseek(file, 0, SEEK_END);
        long size = ftell(file);
        fseek(file, 0, SEEK_SET);

        char* encryptedData = malloc(size + 1);
        if (encryptedData == NULL) {
            perror("Error allocating memory for encrypted data");
            fclose(file);
            return 1;
        }

        int bytesRead = fread(encryptedData, 1, size, file);    //gets exact length
        encryptedData[size] = '\0';
        fclose(file);

        xorEncryptDecrypt(encryptedData, bytesRead, key);

        //completion message
        printf("Decrypted message: %s\n", encryptedData);
        printf("Decryption is completed!\n");

        free(encryptedData);
    }
    else {
        printf("Invalid choice. Please enter 'encrypt' or 'decrypt'.\n");
    }

    return 0;
}