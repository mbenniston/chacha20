cmake_minimum_required(VERSION 3.11)

add_executable(ChaCha20-Example "example.c")
target_link_libraries(ChaCha20-Example PRIVATE ChaCha20)