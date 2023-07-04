#include "chacha.h"
#include <string.h>
#include <stdio.h>
#include <assert.h>

#define CONSTANT_TO_UINT32(string) (((uint32_t)string[0]) | ((uint32_t)string[1] << 8) | ((uint32_t)string[2] << 16) | ((uint32_t)string[3] << 24))

// Utility function declarations
static inline void chacha_double_round(uint32_t* matrix);
static inline void chacha_quarter_round(uint32_t *a_ref, uint32_t *b_ref, uint32_t *c_ref, uint32_t *d_ref);
static inline void chacha_add_matrix(uint32_t* dest, const uint32_t* left, const uint32_t* right);

static inline uint32_t chacha_bytes_to_uint32(uint8_t a, uint8_t b, uint8_t c, uint8_t d);

// Uint32 operations
static inline uint32_t chacha_uint32_add(uint32_t left, uint32_t right);
static inline uint32_t chacha_uint32_xor(uint32_t left, uint32_t right);
static inline uint32_t chacha_uint32_left_rotate(uint32_t value, int rotateAmount);

void chacha_init_matrix(uint32_t* dest_matrix, const uint8_t* key, const uint8_t* counter, const uint8_t* nonce) {
    assert(dest_matrix != NULL);
    assert(key != NULL);
    assert(counter != NULL);
    assert(nonce != NULL);

    // Load constant
    dest_matrix[0] = CONSTANT_TO_UINT32("expa");
    dest_matrix[1] = CONSTANT_TO_UINT32("nd 3");
    dest_matrix[2] = CONSTANT_TO_UINT32("2-by");
    dest_matrix[3] = CONSTANT_TO_UINT32("te k");

    // Load 256-bit key
    dest_matrix[4] = chacha_bytes_to_uint32(key[0], key[1], key[2], key[3]);
    dest_matrix[5] = chacha_bytes_to_uint32(key[4], key[5], key[6], key[7]); 
    dest_matrix[6] = chacha_bytes_to_uint32(key[8], key[9], key[10], key[11]); 
    dest_matrix[7] = chacha_bytes_to_uint32(key[12], key[13], key[14], key[15]); 
    dest_matrix[8] = chacha_bytes_to_uint32(key[16], key[17], key[18], key[19]); 
    dest_matrix[9] = chacha_bytes_to_uint32(key[20], key[21], key[22], key[23]); 
    dest_matrix[10] = chacha_bytes_to_uint32(key[24], key[25], key[26], key[27]); 
    dest_matrix[11] = chacha_bytes_to_uint32(key[28], key[29], key[30], key[31]); 
    
    // Load 32-bit counter
    dest_matrix[12] = chacha_bytes_to_uint32(counter[0], counter[1], counter[2], counter[3]); 
    
    // Load 96-bit nonce
    dest_matrix[13] = chacha_bytes_to_uint32(nonce[0], nonce[1], nonce[2], nonce[3]); 
    dest_matrix[14] = chacha_bytes_to_uint32(nonce[4], nonce[5], nonce[6], nonce[7]); 
    dest_matrix[15] = chacha_bytes_to_uint32(nonce[8], nonce[9], nonce[10], nonce[11]); 
}

void chacha20_round(uint32_t* matrix) { 
    assert(matrix != NULL);
    
    for(int i = 0; i < CHACHA_NUM_ROUNDS; i+=2) {
        chacha_double_round(matrix);
    }
}

void chacha20_block(const uint32_t* initialMatrix, uint8_t* output) {
    assert(initialMatrix != NULL);
    assert(output != NULL);

    chacha_matrix_t matrix;
    memcpy(matrix, initialMatrix, CHACHA_NUM_WORDS * sizeof(uint32_t));

    chacha20_round(matrix);
    chacha_add_matrix(matrix, matrix, initialMatrix);

    for(int i = 0; i < CHACHA_NUM_WORDS; i++){
        int outIdx = i * 4;
        uint32_t value = matrix[i];
        
        output[outIdx] = value & 0xFF;
        output[outIdx+1] = (value & 0xFF00) >> 8;
        output[outIdx+2] = (value & 0xFF0000) >> 16;
        output[outIdx+3] = (value & 0xFF000000) >> 24;
    }
}

static inline void chacha_double_round(uint32_t* matrix) {
    chacha_quarter_round(&matrix[0], &matrix[4], &matrix[8], &matrix[12]);
    chacha_quarter_round(&matrix[1], &matrix[5], &matrix[9], &matrix[13]);
    chacha_quarter_round(&matrix[2], &matrix[6], &matrix[10], &matrix[14]);
    chacha_quarter_round(&matrix[3], &matrix[7], &matrix[11], &matrix[15]);

    chacha_quarter_round(&matrix[0], &matrix[5], &matrix[10], &matrix[15]);
    chacha_quarter_round(&matrix[1], &matrix[6], &matrix[11], &matrix[12]);
    chacha_quarter_round(&matrix[2], &matrix[7], &matrix[8], &matrix[13]);
    chacha_quarter_round(&matrix[3], &matrix[4], &matrix[9], &matrix[14]);
}

static inline void chacha_quarter_round(uint32_t *a_ref, uint32_t *b_ref, uint32_t *c_ref, uint32_t *d_ref) {
    uint32_t a = *a_ref, b = *b_ref, c = *c_ref, d = *d_ref;

    a = chacha_uint32_add(a, b);
    d = chacha_uint32_left_rotate(chacha_uint32_xor(d, a), 16);
    c = chacha_uint32_add(c,d);
    b = chacha_uint32_left_rotate(chacha_uint32_xor(b,c), 12);
    a = chacha_uint32_add(a, b);
    d = chacha_uint32_left_rotate(chacha_uint32_xor(d, a), 8);
    c = chacha_uint32_add(c,d);
    b = chacha_uint32_left_rotate(chacha_uint32_xor(b,c), 7);

    *a_ref = a;
    *b_ref = b;
    *c_ref = c;
    *d_ref = d;
}

static inline uint32_t chacha_bytes_to_uint32(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return ((uint32_t)a | ((uint32_t)b << 8) | ((uint32_t)c << 16) | ((uint32_t)d << 24));
}

extern uint32_t chacha_byte_array_to_uint32(const uint8_t* bytes) { 
    return bytes[0] | (uint32_t)bytes[1] << 8 | (uint32_t)bytes[2] << 16 | (uint32_t)bytes[3] << 24;
}

extern void chacha_uint32_to_bytes_array(uint8_t* bytes, uint32_t value) { 
    bytes[0] = value & 0xFF;
    bytes[1] = (value & 0xFF00) >> 8;
    bytes[2] = (value & 0xFF0000) >> 16;
    bytes[3] = (value & 0xFF000000) >> 24;
}

static inline void chacha_add_matrix(uint32_t* dest, const uint32_t* left, const uint32_t* right) {
    for(int i = 0; i < CHACHA_NUM_WORDS; i++)
        dest[i] = left[i] + right[i];
}

static inline uint32_t chacha_uint32_add(uint32_t left, uint32_t right) {
    return left + right;
}

static inline uint32_t chacha_uint32_xor(uint32_t left, uint32_t right) {
    return left ^ right;
}

static inline uint32_t chacha_uint32_left_rotate(uint32_t value, int rotateAmount) {
    return (value << rotateAmount) | (value >> (32 - rotateAmount));
}

