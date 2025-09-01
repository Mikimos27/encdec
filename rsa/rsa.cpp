#include "rsa.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>
#include <cstdio>
#include <cstring>

#include <string>
#include <iostream>


RSA_keys::RSA_keys(){
    prv = EVP_PKEY_new();
    pub = EVP_PKEY_new();
    keysize = 0;
}
RSA_keys::~RSA_keys(){
    if(prv != NULL) EVP_PKEY_free(prv);
    if(pub != NULL) EVP_PKEY_free(pub);
}


#include "rsa_PUBMAN.cpp"
#include "rsa_PRVMAN.cpp"




void RSA_keys::set_key(EVP_PKEY** keys){

}
void RSA_keys::get_key(EVP_PKEY** keys){

}


void RSA_keys::gen_key_pair(int keysize){
    if(keysize % 8){
        ///////////////////////////////////////////////////////////////
    }
    EVP_PKEY_CTX* ctx = nullptr;
    EVP_PKEY* pkey = nullptr;
    unsigned int primes = 2;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);//change to FIPS
    do{

        if(!ctx){
            std::cerr << "EVP_PKEY_CTX_new_from_name() failed\n";
            break;
        }
        if(EVP_PKEY_keygen_init(ctx) <= 0){
            std::cerr << "EVP_PKEY_keygen_init() failed\n";
            break;
        }
        if(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, keysize) <= 0){
            std::cerr << "EVP_PKEY_CTX_set_rsa_keygen_bits() failed\n";
            break;
        }
        if(EVP_PKEY_CTX_set_rsa_keygen_primes(ctx, primes) <= 0){
            std::cerr << "EVP_PKEY_CTX_set_rsa_keygen_primes() failed\n";
            break;
        }
        if(EVP_PKEY_generate(ctx, &pkey) <= 0){
            std::cerr << "EVP_PKEY_generate() failed\n";
            break;
        }

    }while(0);

    EVP_PKEY_CTX_free(ctx);


    EVP_PKEY_free(this->prv);
    EVP_PKEY_free(this->pub);
    prv = pkey;
    pkey = nullptr;

    pub = _extract_pub(prv);
    this->keysize = keysize;
}


