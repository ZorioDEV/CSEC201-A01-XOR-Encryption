#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define CHOICE_SIZE   16
#define MESSAGE_SIZE  256
#define FILENAME_SIZE 256
#define KEY_SIZE      32

/* Upper bound on a file we are willing to load. Also catches the case where
   fopen succeeds on something that is not a regular file (a directory opens
   fine on many systems and reports a nonsense size). */
#define MAX_FILE_SIZE (64L * 1024L * 1024L)

   /* Result of a single attempt at reading one line from stdin. */
typedef enum {
    READ_OK,
    READ_EMPTY,     /* user just pressed Enter                    */
    READ_TOO_LONG,  /* line did not fit in the buffer             */
    READ_EOF        /* stdin closed / error: stop asking          */
} ReadStatus;

/* Works on raw bytes, so null bytes and high-bit bytes survive the round trip.
   keyLen == 0 is rejected before we ever get here, but guard anyway: a zero
   key length would make "i % keyLen" divide by zero and kill the process. */
void xorEncryptDecrypt(char* message, size_t length, const char* key) {
    size_t keyLen = strlen(key);
    if (keyLen == 0) {
        return;
    }
    for (size_t i = 0; i < length; i++) {
        message[i] = (char)((unsigned char)message[i] ^ (unsigned char)key[i % keyLen]);
    }
}

/* Reads one line, strips the newline, and drains any overflow so the leftover
   characters cannot leak into the next prompt. */
static ReadStatus readLine(const char* prompt, char* buffer, size_t size) {
    printf("%s", prompt);
    fflush(stdout);

    if (fgets(buffer, (int)size, stdin) == NULL) {
        buffer[0] = '\0';
        return READ_EOF;
    }

    size_t len = strcspn(buffer, "\n");
    int overflowed = (buffer[len] != '\n');   /* no newline => line was cut off */
    buffer[len] = '\0';

    if (overflowed) {
        int c;
        while ((c = getchar()) != '\n' && c != EOF) {
            /* discard the rest of the oversized line */
        }
        return READ_TOO_LONG;
    }

    return (len == 0) ? READ_EMPTY : READ_OK;
}

/* Keeps re-prompting until a non-empty line that fits is entered.
   Returns 0 only on end of input, so the loop can never spin forever. */
static int promptLine(const char* prompt, char* buffer, size_t size, const char* label) {
    for (;;) {
        switch (readLine(prompt, buffer, size)) {
        case READ_OK:
            return 1;
        case READ_EMPTY:
            printf("Error: %s cannot be empty. Please try again.\n", label);
            break;
        case READ_TOO_LONG:
            printf("Error: %s must be at most %zu characters. Please try again.\n",
                label, size - 1);
            break;
        case READ_EOF:
            fprintf(stderr, "\nError: no input available for %s. Exiting.\n", label);
            return 0;
        }
    }
}

static int doEncrypt(void) {
    char message[MESSAGE_SIZE], filename[FILENAME_SIZE], key[KEY_SIZE];

    if (!promptLine("Enter the string to encrypt: ", message, sizeof(message), "the message")) return 1;
    if (!promptLine("Enter filename to save encrypted data: ", filename, sizeof(filename), "the filename")) return 1;
    if (!promptLine("Enter key: ", key, sizeof(key), "the key")) return 1;

    size_t length = strlen(message);

    FILE* file = fopen(filename, "wb");   /* binary: no newline translation */
    if (file == NULL) {
        perror("Error opening file for writing");
        return 1;
    }

    xorEncryptDecrypt(message, length, key);

    size_t written = fwrite(message, 1, length, file);
    if (written != length || ferror(file)) {
        fprintf(stderr, "Error: only %zu of %zu bytes could be written to %s\n",
            written, length, filename);
        fclose(file);
        return 1;
    }

    /* Buffered data is flushed here, so write errors can surface at close. */
    if (fclose(file) != 0) {
        perror("Error closing file after writing");
        return 1;
    }

    printf("%zu bytes were written to %s\n", length, filename);
    printf("Encryption is completed!\n");
    return 0;
}

static int doDecrypt(void) {
    char filename[FILENAME_SIZE], key[KEY_SIZE];

    if (!promptLine("Enter filename to read encrypted data: ", filename, sizeof(filename), "the filename")) return 1;
    if (!promptLine("Enter key: ", key, sizeof(key), "the key")) return 1;

    FILE* file = fopen(filename, "rb");   /* binary: 0x0D/0x1A are just data */
    if (file == NULL) {
        perror("Error opening file for reading");
        return 1;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        perror("Error seeking to end of file");
        fclose(file);
        return 1;
    }

    long size = ftell(file);
    if (size < 0) {
        perror("Error determining file size");
        fclose(file);
        return 1;
    }
    rewind(file);

    if (size == 0) {
        fprintf(stderr, "Error: %s is empty, there is nothing to decrypt.\n", filename);
        fclose(file);
        return 1;
    }

    if (size > MAX_FILE_SIZE) {
        fprintf(stderr, "Error: %s is not a readable regular file, or is larger "
            "than the %ld byte limit.\n", filename, MAX_FILE_SIZE);
        fclose(file);
        return 1;
    }

    char* encryptedData = malloc((size_t)size + 1);
    if (encryptedData == NULL) {
        perror("Error allocating memory for encrypted data");
        fclose(file);
        return 1;
    }

    size_t bytesRead = fread(encryptedData, 1, (size_t)size, file);
    if (bytesRead != (size_t)size || ferror(file)) {
        fprintf(stderr, "Error: read was truncated, got %zu of %ld bytes from %s\n",
            bytesRead, size, filename);
        free(encryptedData);
        fclose(file);
        return 1;
    }
    encryptedData[size] = '\0';
    fclose(file);

    xorEncryptDecrypt(encryptedData, bytesRead, key);

    /* fwrite, not printf("%s"), so a null byte in the plaintext does not
       silently cut the output short. */
    printf("Decrypted message: ");
    fwrite(encryptedData, 1, bytesRead, stdout);
    printf("\n");
    printf("%zu bytes were read from %s\n", bytesRead, filename);
    printf("Decryption is completed!\n");

    free(encryptedData);
    return 0;
}

int main(void) {
    char choice[CHOICE_SIZE];

    for (;;) {
        if (!promptLine("Enter 'encrypt' or 'decrypt': ", choice, sizeof(choice), "your choice")) {
            return 1;
        }
        if (strcmp(choice, "encrypt") == 0) {
            return doEncrypt();
        }
        if (strcmp(choice, "decrypt") == 0) {
            return doDecrypt();
        }
        printf("Invalid choice '%s'. Please enter 'encrypt' or 'decrypt'.\n", choice);
    }
}