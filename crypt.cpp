#include "aes/aes_256_gcm.h"
#include "rsa/rsa.h"
extern "C"{
#include <openssl/pem.h>
#include <openssl/err.h>
}
#include <iostream>
#include <cstdio>
#include <cstddef>
#include <cstring>
#include <string>
#define OPENSSL_API_COMPAT 0x30500010

using std::size_t;
using uchar = unsigned char;

void print_hex(const char* name, const uchar* str, size_t len){
    std::printf("%s = ", name);
    for(size_t i = 0; i < len; i++){
        std::printf("%02x", str[i]);
    }
    std::printf("\n");
}

/*
int main(int argc, char** argv){
    if(argc > 1){
        std::cerr << "Too many args\n";
        return 1;
    }

    std::string input;
    std::getline(std::cin, input);
    int len = (int)input.length();
    uchar* in = new uchar[len]{0};
    uchar* cipher = new uchar[len]{0};
    uchar* out = new uchar[len]{0};


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
    
    std::cout << "Decrypted: "; std::printf("\n");
    for(int i = 0; i < len; i++){
        std::printf("%c", (char)out[i]);
    }
    std::printf("\n");


    delete[] in;
    delete[] cipher;
    delete[] out;
    return 0;
}*/


int main(int argc, char** argv){
    int keysize = 4096;
    if(argc < 2){
        std::cout << "No key size given\nUsing default: 4096\n";
    }
    else {
        try{
            keysize = std::stoi(argv[1]);
        }catch(...){
            std::cerr << "NAN given\n";
            return 1;
        }
    }
    RSA_keys rsa;
    if(rsa.gen_key_pair(keysize) < 0){
        std::cerr << "Keys can't be generated\n";
        return 1;
    }
    rsa.write_pubPEM("pub.pem");
    rsa.write_prvPEM("prv.pem", "e");


    char msg[] = "Habla habla habla"; 
    rsa.encrypt((unsigned char*)msg, sizeof(msg));

    int size = rsa.get_out_size();
    unsigned char* enc = new unsigned char[size];
    std::strcpy((char*)enc, (char*)rsa.get_out_buff());
    //rsa.decrypt(enc);

    std::printf("%d\n", size);



    //print_hex("encrypted string", enc, size);


    //ERR_print_errors_fp(stderr);
    delete[] enc;
    return 0;
}
