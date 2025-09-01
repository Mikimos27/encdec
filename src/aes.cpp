extern "C"{
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
}
#include <cstdio>
#include <cstddef>
#include <cstring>

#include <string>
#include <iostream>
#include "../hdr/aes.h"
#include "../hdr/error.h"


using uchar = unsigned char;

AES_GCM::AES_GCM(const uchar* key, const char* aad){
    memcpy(this->key, key, AES_GCM::KEYLEN);


    int aad_len = std::strlen(aad);
    this->aad = new char[aad_len + 1];
    std::strcpy(this->aad, aad);
    genIV();
}

AES_GCM::AES_GCM(const char* aad)
: tag{0} {
    RAND_bytes(key, sizeof(key));
    int aad_len = std::strlen(aad);
    this->aad = new char[aad_len + 1];
    std::strcpy(this->aad, aad);
    genIV();
}
AES_GCM::AES_GCM(const AES_GCM& other){
    memcpy(this->key, other.key, AES_GCM::KEYLEN);
    memcpy(this->iv, other.iv, AES_GCM::IVLEN);
    memcpy(this->tag, other.tag, AES_GCM::TAGLEN);

    int aad_len = std::strlen(other.aad);
    this->aad = new char[aad_len + 1];
    std::strcpy(this->aad, other.aad);
}
AES_GCM::AES_GCM(AES_GCM&& other){
    memcpy(this->key, other.key, AES_GCM::KEYLEN);
    memcpy(this->iv, other.iv, AES_GCM::IVLEN);
    memcpy(this->tag, other.tag, AES_GCM::TAGLEN);

    this->aad = other.aad;
    other.aad = nullptr;
}
AES_GCM::~AES_GCM(){
    OPENSSL_cleanse((void*)this->key, AES_GCM::KEYLEN);
    delete[] aad;
    aad = nullptr;
    ERR_print_errors_fp(stderr);
}

ErrorType AES_GCM::gen_key(){
    return RAND_bytes(key, sizeof(key)) == 1 ? None : KeygenError;
}
ErrorType AES_GCM::genIV(){
    auto err = RAND_bytes(iv, sizeof(iv));
    sameIV = false;
    return err == 1 ? None : KeygenError;
}

ErrorType AES_GCM::encrypt(const uchar* plaintext, uchar* ciphertext, int length){
    if(sameIV) return SameIV;
    EVP_CIPHER_CTX* ctx = nullptr;
    EVP_CIPHER* cipher = nullptr;
    int outlen = 0;
    int tmplen = 0;


    ctx = EVP_CIPHER_CTX_new();
    cipher = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);


    auto err = [&]() -> ErrorType{
        if(!ctx || !cipher){
            std::cerr << "Fetch failed\n";
            return OSSLError;
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
            return EncryptionError;
        }
        if(!EVP_EncryptUpdate(ctx, NULL, &outlen, (uchar*)aad, strlen(aad))){
            std::cerr << "AAD addition failed\n";
            return EncryptionError;
        }
        if(!EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, plen)){
            std::cerr << "Encrypting plaintext failed\n";
            return EncryptionError;
        }
        if(!EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &tmplen)){
            std::cerr << "Encryption finalization failed\n";
            return EncryptionError;
        }
        OSSL_PARAM get_params[] = {
            OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, TAGLEN),
            OSSL_PARAM_END
        };
        if(!EVP_CIPHER_CTX_get_params(ctx, get_params)){
            std::cerr << "Tag extraction on encryption failed\n";
            return EncryptionError;
        }
        return None;
    }();

    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);
    sameIV = true; //???? what if fail???

    return err;
}
ErrorType AES_GCM::decrypt(const uchar* ciphertext, uchar* plaintext, int length){
    EVP_CIPHER_CTX* ctx = nullptr;
    EVP_CIPHER* cipher = nullptr;
    int outlen = 0;
    int tmplen = 0;
    std::size_t ivlen = IVLEN;
    ctx = EVP_CIPHER_CTX_new();
    cipher = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);

    auto err = [&]() -> ErrorType{
        if(!ctx || !cipher){
            std::cerr << "Can't fetch cipher\n";
            return OSSLError;
        }
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN, &ivlen),
            OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, TAGLEN),
            OSSL_PARAM_END
        };
        if(!EVP_DecryptInit_ex2(ctx, cipher, key, iv, params)){
            std::cerr << "Decrypt init failed\n";
            return DecryptionError;
        }
        if(!EVP_DecryptUpdate(ctx, NULL, &outlen, (uchar*)aad, std::strlen(aad))){
            std::cerr << "Decrypt AAD failed\n";
            return DecryptionError;
        }
        if(!EVP_DecryptUpdate(ctx, plaintext, &outlen, ciphertext, length)){
            std::cerr << "Decrypt ciphertext failed\n";
            return DecryptionError;
        }
        if(!EVP_DecryptFinal_ex(ctx, plaintext + outlen, &tmplen)){
            std::cerr << "Decryption failed: tag mismatch, tampering or bad decryption key\n";
            return DecryptionError;
        }
        return None;
    }();

    ERR_print_errors_fp(stderr);
    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);
    return err;
}

const unsigned char* AES_GCM::get_tag(){
    return tag; 
}
const unsigned char* AES_GCM::get_key(){
    return key; 
}
const unsigned char* AES_GCM::get_iv(){
    return iv; 
}

const char* AES_GCM::get_aad(){
    return aad;
}


ErrorType AES_GCM::set_key(const unsigned char (&arr)[KEYLEN]){
    bool bad = true;
    for(std::size_t i = 0; i < IVLEN; i++){
        if(bad && arr[i] != 0) bad = false;
        key[i] = arr[i];
    }
    return bad ? BadInput : None;
}

ErrorType AES_GCM::set_iv(const unsigned char (&arr)[IVLEN]){
    bool bad = true;
    for(std::size_t i = 0; i < IVLEN; i++){
        if(bad && arr[i] != 0) bad = false;
        iv[i] = arr[i];
    }
    sameIV = false;
    return bad ? BadInput : None;
}

ErrorType AES_GCM::set_aad(const char* arr){
    size_t newlen = std::strlen(arr);
    if(newlen <= 0) return BadInput;
    OPENSSL_cleanse((void*)this->key, AES_GCM::KEYLEN);
    delete[] aad;
    aad = (char*)OPENSSL_malloc(newlen + 1);

    if(!aad) return OSSLError;

    for(size_t i = 0; i < newlen; i++){
        aad[i] = arr[i];
    }
    aad[newlen] = 0;
    return None;
}
