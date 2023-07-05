/// @file chacha_stream.h
/// @author mbenniston
/// @brief Utility functions for encrypting streams with XChaCha20
#ifdef __cplusplus
extern "C" {
#endif

#ifndef CHACHA_STREAM_H
#define CHACHA_STREAM_H
#include <stddef.h>
#include "chacha.h"

/// @brief Holds state of the ChaCha stream 
typedef struct {
    chacha_matrix_t matrix;
    uint8_t block[64];
    uint8_t current_byte_index;
} chacha_stream_t;

/// @brief Initializes a chacha strem with a given key, starting block index and nonce.
/// @param stream The stream to be initialized
/// @param key Array of 32-bytes to be used as the key 
/// @param start_block_index The number the block counter should be initialized to.
/// @param nonce Array of 12-bytes to be used as the nonce.
void chacha_stream_init(chacha_stream_t* stream, const uint8_t* key, uint32_t start_block_index, const uint8_t* nonce);

/// @brief Encrypts provided plaintext and progresses block counter of the stream
/// @param stream The stream to be used to encrypt the plaintext
/// @param plaintext The plaintext to be encrypted
/// @param plaintext_length The number of plaintext bytes to be encrytped
/// @note The plaintext is encrypted in place
void chacha_stream_encrypt(chacha_stream_t* stream, uint8_t* plaintext, size_t plaintext_length);

/// @brief Gets the next byte from the keystream 
/// @param stream The stream to be used to provide the keystream
/// @return The next byte of keystream that can be used to encrypt plaintext
uint8_t chacha_stream_next_byte(chacha_stream_t* stream);

/// @brief Retrieves a given amount of bytes from the keystream
/// @param stream The stream to be used to provide the keystream
/// @param bytes A pointer to where the keystream bytes will be written to
/// @param num_bytes Then number of keystream bytes to be retrieved
void chacha_stream_next_bytes(chacha_stream_t* stream, uint8_t* bytes, size_t num_bytes);

/// @brief Decodes the block counter from the chacha matrix
/// @param stream The stream the block counter will be read from
/// @return The current block counter from the given stream
uint32_t chacha_stream_get_counter(const chacha_stream_t* stream);

/// @brief Encodes a given number as the block counter in the chacha matrix
/// @param stream The stream the block counter will be written to
/// @param block_index The block index the stream should have
/// @note This also resets the byte index of the stream to zero, so encryption will
///       start from the block index provided
void chacha_stream_set_counter(chacha_stream_t* stream, uint32_t block_index);

#endif //CHACHA_STREAM_H

#ifdef __cplusplus
}
#endif