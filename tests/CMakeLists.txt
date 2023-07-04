cmake_minimum_required(VERSION 3.11)

add_executable(ChaCha20-Tests "chacha_tests.c")
target_link_libraries(ChaCha20-Tests PRIVATE Unity ChaCha20)