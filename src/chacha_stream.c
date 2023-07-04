#include "chacha_stream.h"
#include <assert.h>
#include <stddef.h>

#include <stdio.h>

#define CHACHA_BLOCK_COUNTER_WORD_INDEX 12

void chacha_stream_init(chacha_stream_t* stream, const uint8_t* key, uint32_t start_block_index, const uint8_t* nonce) { 
    assert(stream != NULL);
    assert(key != NULL);
    assert(nonce != NULL);

    chacha_counter_t counter_bytes;
    chacha_uint32_to_bytes_array(counter_bytes, start_block_index);

    chacha_init_matrix(stream->matrix, key, counter_bytes, nonce);
    stream->current_byte_index = CHACHA_BLOCKLEN;
}

uint8_t chacha_stream_next_byte(chacha_stream_t* stream) { 
    assert(stream != NULL);
     
    if(stream->current_byte_index >= CHACHA_BLOCKLEN) {
        // reset byte offset into block
        stream->current_byte_index = 0;

        // get new block
        chacha20_block(stream->matrix, stream->block);
        
        // increment counter
        uint32_t counter = chacha_stream_get_counter(stream);
        ++counter;
        chacha_uint32_to_bytes_array((uint8_t*)(stream->matrix + CHACHA_BLOCK_COUNTER_WORD_INDEX), counter);
    }

    return stream->block[stream->current_byte_index++];
}

void chacha_stream_next_bytes(chacha_stream_t* stream, uint8_t* bytes, size_t num_bytes) {
    assert(stream != NULL);
    assert(bytes != NULL);

    for(size_t i = 0; i < num_bytes; i++) {
        bytes[i] = chacha_stream_next_byte(stream);
    }
}

void chacha_stream_encrypt(chacha_stream_t* stream, uint8_t* bytes, size_t num_bytes) {
    assert(stream != NULL);
    assert(bytes != NULL);

    for(size_t i = 0; i < num_bytes; i++) {
        bytes[i] ^= chacha_stream_next_byte(stream);
    }
}

uint32_t chacha_stream_get_counter(const chacha_stream_t* stream) { 
    assert(stream != NULL);
    
    return chacha_byte_array_to_uint32((uint8_t*)(stream->matrix + CHACHA_BLOCK_COUNTER_WORD_INDEX));
}

void chacha_stream_set_counter(chacha_stream_t* stream, uint32_t block_index) { 
    assert(stream != NULL);

    chacha_uint32_to_bytes_array((uint8_t*)(stream->matrix + CHACHA_BLOCK_COUNTER_WORD_INDEX), block_index);
    stream->current_byte_index = CHACHA_BLOCKLEN;
}

