#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "chacha.h"
#include "chacha_print.h"
#include "chacha_stream.h"

typedef void (*profile_func_t)();

clock_t profile_function(profile_func_t function, const char* function_name) {
    clock_t start = clock(), end;
    function();
    end = clock();
    clock_t duration = end - start;
    printf("function: \"%s\" took %ld ticks, %ldms\n", function_name, duration, duration * 1000 / CLOCKS_PER_SEC);
    return duration;
}

#define PROFILE_FUNCTION(function) profile_function(function, #function)

void test_chacha_stream()
{
    chacha_key_t key;
    chacha_nonce_t nonce;
    chacha_stream_t stream;
    uint8_t keystream[CHACHA_BLOCKLEN*2];
    
    memset(key, 0, sizeof(key));
    memset(nonce, 0, sizeof(nonce));
    chacha_stream_init(&stream, key, 0, nonce);

    for(int i = 0; i < 50000; i++) { 
        chacha_stream_next_bytes(&stream, keystream, sizeof(keystream));
    }
}

int main(void) {
    clock_t duration = PROFILE_FUNCTION(test_chacha_stream);
    long duration_ms = 1000l * duration / CLOCKS_PER_SEC;
    long throughput = 1000l * (50000l * 2l * CHACHA_BLOCKLEN) / duration_ms;
    printf("thoughput: %ld bytes per second, or %ld MB/s\n", throughput, throughput / (1000 * 1000));
    return 0;
}