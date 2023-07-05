/// @file chacha_print.h
/// @author mbenniston
/// @brief Utiltiy functions for printing output from various stages of algorithm
#ifdef __cplusplus
extern "C"
{
#endif

#ifndef CHACHA_PRINT_H
#define CHACHA_PRINT_H
#include <stddef.h>
#include <inttypes.h>

    /// @brief Prints the chacha matrix encoded as 4x4 32-bit words
    /// @param matrix Pointer to matrix, must be of length 16
    void chacha_print_matrix_internals(const uint32_t *matrix);

    /// @brief Prints the chacha matrix encoded as a stream of bytes that
    ///        would be used for encryption
    /// @param matrix Pointer to matrix, mustbe of length 16
    void chacha_print_matrix_as_keystream(const uint32_t *matrix);

    /// @brief Prints the output block of keystream bytes
    /// @param block Block of 64 bytes
    void chacha_print_block_as_keystream(const uint8_t *block);

    /// @brief Print given bytes as hex
    /// @param bytes Array of bytes to print
    /// @param num_bytes Number of bytes to print
    void chacha_print_bytes(const uint8_t *bytes, size_t num_bytes);

    /// @brief Print given characters
    /// @param characters Array of characters
    /// @param num_characters Number of characters to print
    void chacha_print_characters(const char *characters, size_t num_characters);

    /// @brief Parses a character as a hex digit
    /// @param c The character to be parsed
    /// @return The integer value of the hex digit (0-15)
    /// @note Triggers an assert if the character is not a valid hex digit in debug mode,
    ///       otherwise returns 0 for any other character.
    uint8_t chacha_char_to_int_hex(char c);

    /// @brief Parses a string of hex digits as 256-bit chacha key
    /// @param dest_key Array of bytes where the key will be written to, must be 32-bytes
    /// @param str_key Null terminated string representing the key in hex, must be of length 64
    /// @note Triggers an assert if the key string is not exactly of that size
    void chacha_string_to_key(uint8_t *dest_key, const char *str_key);

    /// @brief Parses a string of hex digits as the 32-bit counter
    /// @param dest_counter Array of bytes where the counter will be written to
    /// @param str_counter Null terminated string representing the counter in hex, must be of length 8
    /// @note Triggers an assert if the counter string is not exactly of that size
    void chacha_string_to_counter(uint8_t *dest_counter, const char *str_counter);

    /// @brief Parses a string of hex digits as the 96-bit nonce
    /// @param dest_nonce Array of bytes where the nonce will be written to
    /// @param str_nonce Null terminated string representing the nonce in hex, must be of length 24
    /// @note Triggers an assert if the counter string is not exactly of that size
    void chacha_string_to_nonce(uint8_t *dest_nonce, const char *str_nonce);

#endif // CHACHA_PRINT_H

#ifdef __cplusplus
}
#endif