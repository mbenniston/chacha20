#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "unity.h"
#include "chacha.h"
#include "chacha_print.h"
#include "chacha_stream.h"
#include <stdlib.h>

void setUp(){}
void tearDown(){}

void test_chacha_block(const char* key_str, uint32_t counter_val, const char* nonce_str, const char* expected_block) {
    chacha_key_t key;
    chacha_counter_t counter;
    chacha_nonce_t nonce;

    chacha_matrix_t matrix;
    chacha_block_t block;

    chacha_string_to_key(key, key_str);
    chacha_uint32_to_bytes_array(counter, counter_val);
    chacha_string_to_nonce(nonce, nonce_str);

    chacha_init_matrix(matrix, key, counter, nonce);
    chacha20_block(matrix, block);

    size_t expected_bytes = strlen(expected_block) / 2;

    for(size_t i = 0; i < expected_bytes; i++) {
        uint8_t actual_byte = block[i];
        uint8_t expected_byte = chacha_char_to_int_hex(expected_block[i*2])<<4 | chacha_char_to_int_hex(expected_block[i*2+1]);
        TEST_ASSERT_EQUAL(expected_byte, actual_byte);
    }
}

void test_chacha_encryption(const char* key_str, uint32_t counter_val, const char* nonce_str, const uint8_t* plaintext, size_t plaintext_length, const char* expected_ciphertext) {

    chacha_key_t key;
    chacha_nonce_t nonce;
    chacha_stream_t stream;

    chacha_string_to_key(key, key_str);
    chacha_string_to_nonce(nonce, nonce_str);
    chacha_stream_init(&stream, key, counter_val, nonce);

    uint8_t* buffer = malloc(plaintext_length);
    memcpy(buffer, plaintext, plaintext_length);

    chacha_stream_encrypt(&stream, buffer, plaintext_length);

    size_t expected_bytes = strlen(expected_ciphertext) / 2;

    for (size_t i = 0; i < expected_bytes; i++) {
        uint8_t actual_byte = buffer[i];
        uint8_t expected_byte = chacha_char_to_int_hex(expected_ciphertext[i * 2]) << 4 | chacha_char_to_int_hex(expected_ciphertext[i * 2 + 1]);

        TEST_ASSERT_EQUAL(expected_byte, actual_byte);
    }

    free(buffer);
}

void test_chacha_encryption_string(const char* key_str, uint32_t counter_val, const char* nonce_str, const char* plaintext, const char* expected_ciphertext) {
    test_chacha_encryption(key_str, counter_val, nonce_str, plaintext, strlen(plaintext), expected_ciphertext);
}

// https://datatracker.ietf.org/doc/html/draft-agl-tls-chacha20poly1305-04#section-7
void test_chacha_rfc_draft(void)
{

    test_chacha_block(
        "0000000000000000000000000000000000000000000000000000000000000000", 
        0, 
        "000000000000000000000000",
        "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586");

    test_chacha_block(
        "0000000000000000000000000000000000000000000000000000000000000001", 
        0, 
        "000000000000000000000000",
        "4540f05a9f1fb296d7736e7b208e3c96eb4fe1834688d2604f450952ed432d41bbe2a0b6ea7566d2a5d1e7e20d42af2c53d792b1c43fea817e9ad275ae546963");

    test_chacha_block(
        "0000000000000000000000000000000000000000000000000000000000000000", 
        0, 
        "000000000000000000000001",
        "de9cba7bf3d69ef5e786dc63973f653a0b49e015adbff7134fcb7df137821031e85a050278a7084527214f73efc7fa5b5277062eb7a0433e445f41e3");
 
    test_chacha_block(
        "0000000000000000000000000000000000000000000000000000000000000000", 
        0, 
        "000000000100000000000000",
        "ef3fdfd6c61578fbf5cf35bd3dd33b8009631634d21e42ac33960bd138e50d32111e4caf237ee53ca8ad6426194a88545ddc497a0b466e7d6bbdb0041b2f586b");
}

// https://datatracker.ietf.org/doc/rfc7539/
void test_chacha20_rfc_7539_2_3_2(void) {
    test_chacha_block(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 
        1, 
        "000000090000004a00000000", 
        "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e");
}

// https://datatracker.ietf.org/doc/rfc7539/
void test_chacha20_rfc_7539_2_4_2(void) {
    test_chacha_encryption_string("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 1, "000000000000004a00000000",
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
        "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d");
}

// https://datatracker.ietf.org/doc/rfc7539/
void test_chacha20_rfc_7539_a1(void) {
    test_chacha_block(
        "0000000000000000000000000000000000000000000000000000000000000000",
        0,
        "000000000000000000000000",
        "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586");

    test_chacha_block(
        "0000000000000000000000000000000000000000000000000000000000000000",
        1,
        "000000000000000000000000",
        "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f");

    test_chacha_block(
        "0000000000000000000000000000000000000000000000000000000000000001",
        1,
        "000000000000000000000000",
        "3aeb5224ecf849929b9d828db1ced4dd832025e8018b8160b82284f3c949aa5a8eca00bbb4a73bdad192b5c42f73f2fd4e273644c8b36125a64addeb006c13a0");

    test_chacha_block(
        "00ff000000000000000000000000000000000000000000000000000000000000",
        2,
        "000000000000000000000000",
        "72d54dfbf12ec44b362692df94137f328fea8da73990265ec1bbbea1ae9af0ca13b25aa26cb4a648cb9b9d1be65b2c0924a66c54d545ec1b7374f4872e99f096");

    test_chacha_block(
        "0000000000000000000000000000000000000000000000000000000000000000",
        0,
        "000000000000000000000002",
        "c2c64d378cd536374ae204b9ef933fcd1a8b2288b3dfa49672ab765b54ee27c78a970e0e955c14f3a88e741b97c286f75f8fc299e8148362fa198a39531bed6d");
}

// https://datatracker.ietf.org/doc/rfc7539/
void test_chacha20_rfc_7539_a2(void) {
    char buffer[64] = { 0 };

    test_chacha_encryption(
        "0000000000000000000000000000000000000000000000000000000000000000",
        0,
        "000000000000000000000000",
        buffer,
        64,
        "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586");

    test_chacha_encryption_string(
        "0000000000000000000000000000000000000000000000000000000000000001",
        1,
        "000000000000000000000002",
        "Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an \"IETF Contribution\". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to",
        "a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec2a97948bd3722915c8f3d337f7d370050e9e96d647b7c39f56e031ca5eb6250d4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881a7c6132f420e52795042bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85ad00f8449ed8f72d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259dc4b2d0dfb48a6c9139ddd7f76966e928e635553ba76c5c879d7b35d49eb2e62b0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c765989cbcf3daa8b6ccc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e818b04b0bc39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f5869ca52c5b83fa36ff216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e698ced759c3ff9b6477338f3da4f9cd8514ea9982ccafb341b2384dd902f3d1ab7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221");

    test_chacha_encryption_string(
        "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
        42,
        "000000000000000000000002",
        "\x27\x54\x77\x61\x73\x20\x62\x72\x69\x6c\x6c\x69\x67\x2c\x20\x61\x6e\x64\x20\x74\x68\x65\x20\x73\x6c\x69\x74\x68\x79\x20\x74\x6f\x76\x65\x73\x0a\x44\x69\x64\x20\x67\x79\x72\x65\x20\x61\x6e\x64\x20\x67\x69\x6d\x62\x6c\x65\x20\x69\x6e\x20\x74\x68\x65\x20\x77\x61\x62\x65\x3a\x0a\x41\x6c\x6c\x20\x6d\x69\x6d\x73\x79\x20\x77\x65\x72\x65\x20\x74\x68\x65\x20\x62\x6f\x72\x6f\x67\x6f\x76\x65\x73\x2c\x0a\x41\x6e\x64\x20\x74\x68\x65\x20\x6d\x6f\x6d\x65\x20\x72\x61\x74\x68\x73\x20\x6f\x75\x74\x67\x72\x61\x62\x65\x2e",
        "62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf166d3df2d721caf9b21e5fb14c616871fd84c54f9d65b283196c7fe4f60553ebf39c6402c42234e32a356b3e764312a61a5532055716ead6962568f87d3f3f7704c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1");

}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_chacha_rfc_draft);
    RUN_TEST(test_chacha20_rfc_7539_2_3_2);
    RUN_TEST(test_chacha20_rfc_7539_2_4_2);
    RUN_TEST(test_chacha20_rfc_7539_a1);
    RUN_TEST(test_chacha20_rfc_7539_a2);
    return UNITY_END();
}