cmake_minimum_required(VERSION 3.11)

add_executable(ChaCha20-Benchmark "chacha_benchmark.c")
target_link_libraries(ChaCha20-Benchmark PRIVATE ChaCha20)