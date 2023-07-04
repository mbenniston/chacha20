cmake_minimum_required(VERSION 3.11)

add_library(ChaCha20)
target_sources(ChaCha20
PRIVATE
    "chacha.c"
    "chacha_stream.c"
    "chacha_print.c"
)

target_include_directories(ChaCha20 PUBLIC ".")