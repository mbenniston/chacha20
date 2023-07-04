/// @file chacha.h
/// @author mbenniston
/// @brief Implementation of the ChaCha20 algorithm with 12-byte nonce.
///        Only contains block function implementation. For stream operations see 
///        chacha_stream.h
#ifdef __cplusplus
extern "C" {
#endif

#ifndef CHACHA_H
#define CHACHA_H
#include <inttypes.h>

#define CHACHA_KEY_LEN 32
#define CHACHA_NONCE_LEN 12
#define CHACHA_COUNTER_LEN 4
#define CHACHA_BLOCKLEN 64
#define CHACHA_NUM_ROUNDS 20
#define CHACHA_NUM_WORDS 16

// Typedefs for cleaner variable declaration
typedef uint8_t chacha_key_t[CHACHA_KEY_LEN];
typedef uint8_t chacha_nonce_t[CHACHA_NONCE_LEN];
typedef uint8_t chacha_counter_t[CHACHA_COUNTER_LEN];
typedef uint32_t chacha_matrix_t[16];
typedef uint8_t chacha_block_t[CHACHA_BLOCKLEN];

/// @brief Fills the 4x4 word matrix with constant, key, counter and nonce values
/// @param dest Array of 4 unsigned 32-bit words to be initialized
/// @param key Pointer to 32 key bytes
/// @param counter Pointer to 4 byte counter encoded as little endian
/// @param nonce Pointer to 12 byte nonce
void chacha_init_matrix(uint32_t* dest_matrix, const uint8_t* key, const uint8_t* counter, const uint8_t* nonce);

/// @brief Performs a chacha20 round, which consists of 10 double rounds
/// @param matrix The matrix to perform the rounds on
void chacha20_round(uint32_t* matrix);

/// @brief Perform chacha20 using the given matrix as the initial state and write the resulting keystream
///        to the given output buffer
/// @param matrix Pointer to initial matrix state (generated from chacha_init_matrix)
/// @param output Array of 64 bytes where the keystream will be written to.
void chacha20_block(const uint32_t* matrix, uint8_t* output);

/// @brief Decodes a given integer encoded in little endian 
/// @param bytes The integer represented as bytes encoded as little endian
/// @return An integer representing the value of the bytes interpreted as a little endian number
inline uint32_t chacha_byte_array_to_uint32(const uint8_t* bytes);

/// @brief Encodes a given integer into a little endian byte array 
/// @param bytes A pointer to where the integer will be encoded to, must be 4 bytes long
/// @param value The integer to be encoded
inline void chacha_uint32_to_bytes_array(uint8_t* bytes, uint32_t value);

#endif // CHACHA_H

#ifdef __cplusplus
}
#endif