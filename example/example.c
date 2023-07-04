#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <chacha.h>
#include <chacha_stream.h>
#include <chacha_print.h>

int main(void) {
    // copy plaintext to buffer
    char* plaintext = "hello world this is a message that will be encrypted";
    size_t buffer_length = strlen(plaintext);
    uint8_t* buffer = malloc(buffer_length);
    memcpy(buffer, plaintext, buffer_length);

    // setup key and nonce
    chacha_key_t key;
    chacha_nonce_t nonce;

    memcpy(key, 
        "256-bit key     256-bit key     256-bit key     256-bit key     256-bit key     256-bit key     256-bit key     256-bit key     "
        "256-bit key     256-bit key     256-bit key     256-bit key     256-bit key     256-bit key     256-bit key     256-bit key     ", 32);

    chacha_string_to_nonce(nonce, "000000000000000000000000");

    // create stream
    chacha_stream_t stream;
    chacha_stream_init(&stream, key, 0, nonce);

    // print plain text
    puts("plaintext");
    chacha_print_characters(buffer, buffer_length);
    puts("");

    // encrypt buffer
    puts("encrypted");
    chacha_stream_encrypt(&stream, buffer, buffer_length);
    chacha_print_bytes(buffer, buffer_length);
    puts("");

    // decrypt buffer
    puts("decrypted"); 
    
    chacha_stream_set_counter(&stream, 0); // reset counter back to start
    chacha_stream_encrypt(&stream, buffer, buffer_length);
    chacha_print_characters(buffer, buffer_length);

    free(buffer);
}