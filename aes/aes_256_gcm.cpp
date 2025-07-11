#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <cstdio>
#include <cstddef>
#include <cstring>

#include <string>
#include <iostream>
#include "aes_256_gcm.h"


using uchar = unsigned char;


AES_256_GCM_key::AES_256_GCM_key(const char* aad)
: tag{0}, aad{(unsigned char*)aad} {
    RAND_bytes(key, sizeof(key));
    genIV();
}
AES_256_GCM_key::~AES_256_GCM_key(){

}

void AES_256_GCM_key::genIV(){
    RAND_bytes(iv, sizeof(iv));
}

void AES_256_GCM_key::encrypt(const uchar* plaintext, uchar* ciphertext, int length){
    EVP_CIPHER_CTX* ctx = nullptr;
    EVP_CIPHER* cipher = nullptr;
    int outlen = 0;
    int tmplen = 0;
    genIV();


    ctx = EVP_CIPHER_CTX_new();
    cipher = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);


    do{
        if(!ctx || !cipher){
            std::cerr << "Fetch failed\n";
        }
        std::size_t taglen = TAGLEN;
        std::size_t ivlen = IVLEN;
        int plen = length;//Vunurable???????????????????????????
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN, &ivlen),
            OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, &taglen),
            OSSL_PARAM_END
        };

        if(!EVP_EncryptInit_ex2(ctx, cipher, key, iv, params)){
            std::cerr << "Init failed\n";
            break;
        }
        if(!EVP_EncryptUpdate(ctx, NULL, &outlen, aad, strlen((char*)aad))){
            std::cerr << "AAD addition failed\n";
            break;
        }
        if(!EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, plen)){
            std::cerr << "Encrypting plaintext failed\n";
            break;
        }
        if(!EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &tmplen)){
            std::cerr << "Encryption finalization failed\n";
            break;
        }
        OSSL_PARAM get_params[] = {
            OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, TAGLEN),
            OSSL_PARAM_END
        };
        if(!EVP_CIPHER_CTX_get_params(ctx, get_params)){
            std::cerr << "Tag extraction on encryption failed\n";
        }
    }while(0);

    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);
}
void AES_256_GCM_key::decrypt(const uchar* ciphertext, uchar* plaintext, int length){
    EVP_CIPHER_CTX* ctx = nullptr;
    EVP_CIPHER* cipher = nullptr;
    int outlen = 0;
    int tmplen = 0;
    std::size_t ivlen = IVLEN;
    ctx = EVP_CIPHER_CTX_new();
    cipher = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);

    do{
        if(!ctx || !cipher){
            std::cerr << "Can't fetch cipher\n";
            break;
        }
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN, &ivlen),
            OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, TAGLEN),
            OSSL_PARAM_END
        };
        if(!EVP_DecryptInit_ex2(ctx, cipher, key, iv, params)){
            std::cerr << "Decrypt init failed\n";
            break;
        }
        if(!EVP_DecryptUpdate(ctx, NULL, &outlen, aad, std::strlen((char*)aad))){
            std::cerr << "Decrypt AAD failed\n";
            break;
        }
        if(!EVP_DecryptUpdate(ctx, plaintext, &outlen, ciphertext, length)){
            std::cerr << "Decrypt ciphertext failed\n";
            break;
        }
        if(!EVP_DecryptFinal_ex(ctx, plaintext + outlen, &tmplen)){
            std::cerr << "Decryption failed: tag mismatch, tampering or bad decryption key\n";
            break;
        }
    }while(0);

    ERR_print_errors_fp(stderr);
    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);
}

const unsigned char* AES_256_GCM_key::get_tag(){
    return tag; 
}
const unsigned char* AES_256_GCM_key::get_key(){
    return key; 
}
const unsigned char* AES_256_GCM_key::get_iv(){
    return iv; 
}

const unsigned char* AES_256_GCM_key::get_aad(){
    return aad;
}


void AES_256_GCM_key::set_key(unsigned char (&arr)[KEYLEN]){
    for(std::size_t i = 0; i < KEYLEN; i++){
        key[i] = arr[i];
    }
}

void AES_256_GCM_key::set_iv(unsigned char (&arr)[IVLEN]){
    for(std::size_t i = 0; i < KEYLEN; i++){
        iv[i] = arr[i];
    }
}
