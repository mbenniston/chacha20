#include "chacha_print.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "chacha.h"

void chacha_print_matrix_internals(const uint32_t* matrix) {
    assert(matrix != NULL);

    for(int row = 0; row < 4; row++) {
        for(int column = 0; column < 4; column++) {
            uint32_t value = matrix[column + row * 4];
            printf("%08x ", value);
        }
        printf("\n");
    }
}

void chacha_print_matrix_as_keystream(const uint32_t* matrix) {
    assert(matrix != NULL);

    for(int i = 0; i < 16; i++) {
        printf("%02x", (matrix[i] & 0xFFu)>> 0);
        printf("%02x", (matrix[i] & (0xFF00u)) >> 8);
        printf("%02x", (matrix[i] & (0xFF0000u)) >> 16);
        printf("%02x", (matrix[i] & (0xFF000000u)) >> 24);
    }
    printf("\n");
}

void chacha_print_block_as_keystream(const uint8_t* block) {
    assert(block != NULL);

    chacha_print_bytes(block, CHACHA_BLOCKLEN);
}

void chacha_print_bytes(const uint8_t* bytes, size_t num_bytes) {
    assert(bytes != NULL);

    for (int i = 0; i < num_bytes; i++) {
        printf("%02x", bytes[i]);
    }
    printf("\n");
}

void chacha_print_characters(const char* characters, size_t num_characters) {
    assert(characters != NULL);

    for (int i = 0; i < num_characters; i++) {
        printf("%c", characters[i]);
    }
    printf("\n");
}

uint8_t chacha_char_to_int_hex(char c){
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    if (c >= '0' && c <= '9')
        return c - '0';
    
    return 0;
}

void chacha_string_to_key(uint8_t* dest_key, const char* str_key) {
    assert(dest_key != NULL);
    assert(str_key != NULL);
    assert(strlen(str_key) == (CHACHA_KEY_LEN * 2));

    for(int i = 0; i < CHACHA_KEY_LEN; i++)
    {
        int str_idx = i * 2;
        uint8_t byte = 0;
        byte |= chacha_char_to_int_hex(str_key[str_idx]) << 4;
        byte |= chacha_char_to_int_hex(str_key[str_idx + 1]);
        dest_key[i] = byte;
    }
}

void chacha_string_to_counter(uint8_t* dest_counter, const char* str_counter) {
    assert(dest_counter != NULL);
    assert(str_counter != NULL);
    assert(strlen(str_counter) == (CHACHA_COUNTER_LEN * 2));

    for(int i = 0; i < CHACHA_COUNTER_LEN; i++)
    {
        int str_idx = i * 2;
        uint8_t byte = 0;
        byte |= chacha_char_to_int_hex(str_counter[str_idx]) << 4;
        byte |= chacha_char_to_int_hex(str_counter[str_idx + 1]);
        dest_counter[i] = byte;
    }
}

void chacha_string_to_nonce(uint8_t* dest_nonce, const char* str_nonce) {
    assert(dest_nonce != NULL);
    assert(str_nonce != NULL);
    assert(strlen(str_nonce) == (CHACHA_NONCE_LEN * 2));

    for(int i = 0; i < CHACHA_NONCE_LEN; i++)
    {
        int str_idx = i * 2;
        uint8_t byte = 0;
        byte |= chacha_char_to_int_hex(str_nonce[str_idx]) << 4;
        byte |= chacha_char_to_int_hex(str_nonce[str_idx + 1]);
        dest_nonce[i] = byte;
    }
}