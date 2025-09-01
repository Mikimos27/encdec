#include "aes_256_gcm.h"
#include <iostream>
#include <cstdio>
#include <cstddef>
#include <string>

using std::size_t;

void print_hex(const char* name, const unsigned char* str, size_t len){
    printf("%s = ", name);
    for(size_t i = 0; i < len; i++){
        std::printf("%02x", str[i]);
    }
    std::printf("\n");
}


int main(){
    constexpr int length = 20;
    AES_256_GCM_key aes("ExampleAAD");
    char from[length] = {0};
    unsigned char in[length] = {0};
    std::fgets(from, length, stdin);
    for(int i = 0; i < length; i++){
        in[i] = (unsigned char)from[i];
    }
    unsigned char cipher[length];
    aes.encrypt(in, cipher, length);

    print_hex("ciphertext", cipher, length);
    print_hex("tag", aes.get_tag(), AES_256_GCM_key::get_taglen());
    print_hex("iv", aes.get_iv(), AES_256_GCM_key::get_ivlen());
    print_hex("key", aes.get_key(), AES_256_GCM_key::get_keylen());


    unsigned char out[length] = {0};
    char outch[length] = {0};


    aes.decrypt(cipher, out, length);
    
    for(int i = 0; i < length; i++){
        outch[i] = (char)out[i];
    }
    std::cout << "Decrypted: " << outch << '\n';


    return 0;
}
