#include "ed25519.h"
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

#include "ed25519_PUB.cpp"
#include "ed25519_PRV.cpp"
#include "ed25519_crypto.cpp"

Ed25519::Ed25519(){
    this->prv = nullptr;
    this->pub = nullptr;
    keysize = 0;
    out_buff = nullptr;
    out_size = 0;
}
Ed25519::~Ed25519(){
    if(prv != nullptr) _free_key(&prv);
    if(pub != nullptr) _free_key(&pub);
    keysize = 0;
    _clear_buff();
    ERR_print_errors_fp(stderr);
}


void Ed25519::set_key_prv(EVP_PKEY** keys){
    _free_key(&prv);
    prv = *keys;
    *keys = nullptr;

    keysize = EVP_PKEY_get_bits(prv);

    _clear_buff();
    if(_extract_pub(prv, &pub)) std::cerr << "Ed25519::set_key_prv _extract_pub error\n";
}
const EVP_PKEY* const Ed25519::get_key_prv(){
    return prv;
}

void Ed25519::set_key_pub(EVP_PKEY** keys){
    _free_key(&pub);
    _free_key(&prv);
    prv = nullptr;
    pub = *keys;
    *keys = nullptr;

    _clear_buff();
}
const EVP_PKEY* const Ed25519::get_key_pub(){
    return pub;
}

int Ed25519::gen_key_pair(int keysize){
    //if(keysize < 1024) throw std::logic_error("Key must be at least 1024 bits long, ideally equal or larger than 2048 bits");
    if(keysize % 8){
        std::cerr << "Key size not divisible by 8\n";
        return -1;
    }
    _clear_buff();
    EVP_PKEY_CTX* ctx = nullptr;
    EVP_PKEY* pkey = nullptr;
    //unsigned int primes = 2;

    //Problemvvvvv
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "Ed25519", NULL);//change to FIPS
    //ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);//change to FIPS
    //Problem^^^^^
    do{

        if(!ctx){
            std::cerr << "EVP_PKEY_CTX_new_from_name() failed\n";
            break;
        }
        if(EVP_PKEY_keygen_init(ctx) <= 0){
            std::cerr << "EVP_PKEY_keygen_init() failed\n";
            break;
        }
        /*
        if(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, keysize) <= 0){
            std::cerr << "EVP_PKEY_CTX_set_rsa_keygen_bits() failed\n";
            break;
        }
        if(EVP_PKEY_CTX_set_rsa_keygen_primes(ctx, primes) <= 0){
            std::cerr << "EVP_PKEY_CTX_set_rsa_keygen_primes() failed\n";
            break;
        }
        */
        if(EVP_PKEY_generate(ctx, &pkey) <= 0){
            std::cerr << "EVP_PKEY_generate() failed\n";
            break;
        }

    }while(0);

    EVP_PKEY_CTX_free(ctx);


    if(this->prv) _free_key(&this->prv);
    if(this->pub) _free_key(&this->pub);
    prv = pkey;
    pkey = nullptr;

    if(_extract_pub(prv, &pub)) throw std::invalid_argument("Can't extract pub key\n");
    if(!pub) throw std::invalid_argument("BAD in genkey\n");
    this->keysize = keysize;

    return 0;
}


const unsigned char* const Ed25519::get_out_buff(){
    return out_buff;
}
const std::size_t Ed25519::get_out_size(){
    return this->out_size;
}
const std::size_t Ed25519::get_ciph_size(){
    return this->pub == nullptr ? 0 : EVP_PKEY_get_size(this->pub);
}

void Ed25519::_clear_buff(){
    if(out_buff){
        OPENSSL_cleanse(out_buff, out_size);
        OPENSSL_free(out_buff);
    }
    out_buff = nullptr;
    out_size = 0;
}

void Ed25519::_free_key(EVP_PKEY** pkey){
    //static int free_count = 0;
    if(*pkey){
        EVP_PKEY_free(*pkey);
        *pkey = nullptr;
        //free_count++;
        //std::cout << free_count << '\n';
    }
}
