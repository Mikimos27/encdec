#include "aes_256_gcm.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>
#include <cstdio>
#include <cstddef>
#include <string>
#include <cstring>
#include <memory>



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

void AES_256_GCM_key::encrypt(const unsigned char* plain, unsigned char* ciphertext, int length){
    EVP_CIPHER_CTX* ctx = nullptr;
    EVP_CIPHER* cipher = nullptr;
    int outlen = 0;
    int tmplen = 0;
    int clen = 0;
    genIV();


    ctx = EVP_CIPHER_CTX_new();
    cipher = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
    if(!ctx || !cipher){
        std::perror("Fetch failed\n");
    }
    int taglen = TAGLEN;
    int ivlen = IVLEN;
    int plen = length;//Vunurable???????????????????????????
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_int(OSSL_CIPHER_PARAM_IVLEN, &ivlen),
        OSSL_PARAM_construct_int(OSSL_CIPHER_PARAM_AEAD_TAGLEN, &taglen),
        OSSL_PARAM_END
    };

    if(!EVP_EncryptInit_ex2(ctx, cipher, key, iv, params)){
        std::perror("Init failed\n");
    }
    if(!EVP_EncryptUpdate(ctx, NULL, &outlen, aad, strlen((char*)aad))){
        std::perror("Init failed\n");
    }
    if(!EVP_EncryptUpdate(ctx, ciphertext, &outlen, plain, plen)){
        std::perror("Init failed\n");
    }
    clen = outlen;
    if(!EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &tmplen)){
        std::perror("Init failed\n");
    }
    clen += tmplen;
    OSSL_PARAM get_params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, TAGLEN),
        OSSL_PARAM_END
    };
    if(!EVP_CIPHER_CTX_get_params(ctx, get_params)){

    }

    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);
}
std::string AES_256_GCM_key::decrypt(const std::string& ciphertext){
    using std::size_t;
    return "TODO";

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


