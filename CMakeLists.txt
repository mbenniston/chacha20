cmake_minimum_required(VERSION 3.11)

project(ChaCha20-Poly1305)

option(CHACHA_BUILD_TESTS "Build tests" OFF)
option(CHACHA_BUILD_BENCHMARK "Build benchmark" OFF)
option(CHACHA_BUILD_EXAMPLE "Build example" OFF)

add_subdirectory("src")

if(CHACHA_BUILD_TESTS)
    add_subdirectory("deps/unity")
    add_subdirectory("tests")
endif(CHACHA_BUILD_TESTS)

if(CHACHA_BUILD_BENCHMARK)
    add_subdirectory("benchmark")
endif(CHACHA_BUILD_BENCHMARK)

if(CHACHA_BUILD_EXAMPLE)
    add_subdirectory("example")
endif(CHACHA_BUILD_EXAMPLE)