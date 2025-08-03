#include "rsa.h"
extern "C"{
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>
#include <cstdio>
#include <cstring>
}

#include <string>
#include <iostream>
#include <exception>

#include "rsa_PUBMAN.cpp"
#include "rsa_PRVMAN.cpp"
#include "rsa_crypto.cpp"

RSA_keys::RSA_keys(){
    prv = EVP_PKEY_new();
    pub = EVP_PKEY_new();
    keysize = 0;
    out_buff = nullptr;
    out_size = 0;
}
RSA_keys::~RSA_keys(){
    if(prv != NULL) {
        OPENSSL_cleanse(prv, sizeof(prv));
        EVP_PKEY_free(prv);
    }
    if(pub != NULL){
        OPENSSL_cleanse(pub, sizeof(pub));
        EVP_PKEY_free(pub);
    }
    keysize = 0;
    _clear_buff();
    ERR_print_errors_fp(stderr);
}


void RSA_keys::set_key_prv(EVP_PKEY** keys){
    OPENSSL_cleanse(prv, sizeof(prv));
    EVP_PKEY_free(prv);
    prv = *keys;
    *keys = nullptr;

    keysize = EVP_PKEY_get_bits(prv);

    _clear_buff();
    _extract_pub(prv);
}
const EVP_PKEY* const RSA_keys::get_key_prv(){
    return prv;
}

void RSA_keys::set_key_pub(EVP_PKEY** keys){
    OPENSSL_cleanse(pub, sizeof(pub));
    OPENSSL_cleanse(prv, sizeof(prv));
    EVP_PKEY_free(pub);
    EVP_PKEY_free(prv);
    prv = nullptr;
    pub = *keys;
    *keys = nullptr;

    _clear_buff();
}
const EVP_PKEY* const RSA_keys::get_key_pub(){
    return pub;
}

int RSA_keys::gen_key_pair(int keysize){
    if(keysize < 1024) throw std::logic_error("Key must be at least 1024 bits long, ideally equal or larger than 2048 bits");
    if(keysize % 8){
        std::cerr << "Key size not divisible by 8\n";
        return -1;
    }
    _clear_buff();
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


    OPENSSL_cleanse(this->prv, sizeof(this->prv));
    OPENSSL_cleanse(this->pub, sizeof(this->pub));
    EVP_PKEY_free(this->prv);
    EVP_PKEY_free(this->pub);
    prv = pkey;
    pkey = nullptr;

    pub = _extract_pub(prv);
    this->keysize = keysize;

    return 0;
}


const unsigned char* const RSA_keys::get_out_buff(){
    return out_buff;
}
const std::size_t RSA_keys::get_out_size(){
    return this->out_size;
}
const std::size_t RSA_keys::get_ciph_size(){
    return this->pub == nullptr ? 0 : EVP_PKEY_get_size(this->pub);
}

void RSA_keys::_clear_buff(){
    if(out_buff){
        OPENSSL_cleanse(out_buff, sizeof(out_buff));
        OPENSSL_free(out_buff);
    }
    out_buff = nullptr;
    out_size = 0;
}
