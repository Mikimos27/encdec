#include "aes_256_gcm.h"
#include <iostream>
#include <cstdio>
#include <cstddef>
#include <string>
#include <openssl/rand.h>

using std::size_t;
using uchar = unsigned char;

void print_hex(const char* name, const uchar* str, size_t len){
    std::printf("%s = ", name);
    for(size_t i = 0; i < len; i++){
        std::printf("%02x", str[i]);
    }
    std::printf("\n");
}


int main(){

    std::string input;
    std::getline(std::cin, input);
    int len = (int)input.length();
    uchar* in = new uchar[len]{0};
    uchar* cipher = new uchar[len]{0};
    uchar* out = new uchar[len]{0};
    char* outch = new char[len]{0};


    AES_256_GCM_key aes("ExampleAAD");

    for(int i = 0; i < len; i++){
        in[i] = (uchar)input.at(i);
    }
    aes.encrypt(in, cipher, len);

    print_hex("ciphertext", cipher, len);
    print_hex("tag", aes.get_tag(), AES_256_GCM_key::TAGLEN);
    print_hex("iv", aes.get_iv(), AES_256_GCM_key::IVLEN);
    print_hex("key", aes.get_key(), AES_256_GCM_key::KEYLEN);


    aes.decrypt(cipher, out, len);
    
    for(int i = 0; i < len; i++){
        outch[i] = (char)out[i];
    }
    std::cout << "Decrypted: " << outch << '\n';


    delete[] in;
    delete[] cipher;
    delete[] out;
    delete[] outch;
    return 0;
}
