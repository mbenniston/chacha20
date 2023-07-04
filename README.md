# chacha20

This repository contains an implementation of the chacha20 cipher along with utility functions 
for using it in practice. 

This implementation is tested against the vectors put forward in [RFC7539](https://datatracker.ietf.org/doc/rfc7539/)

## Usage

This library can be consumed using the `add_subdirectory` CMake function or by simply copying over the 
required .c/.h files into your project. `/src` contains these files. 
- `chacha.c/h` contains an implementation of the chacha block function.
- `chacha_stream.c/h` contains functions useful for encrypting variable length streams of bytes using chacha.
- `chacha_print.c/h` provides utility functions for printing and reading in various chacha primitives.

## Example 

```c
chacha_stream_t stream;
chacha_stream_init(&stream, key, start_block_index, nonce);

chacha_stream_encrypt(&stream, buffer, buffer_length);
```
See `/example` directory for full example.

## Features to add

- Thorough benchmarking
- More test vectors
- More key and nonce width options
- Poly1305 MAC 

## Reference documents

- Original paper: https://cr.yp.to/chacha/chacha-20080128.pdf
- Test vectors: https://datatracker.ietf.org/doc/rfc7539/
