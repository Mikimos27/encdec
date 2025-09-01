#ifndef AES_256_GCM_H
#define AES_256_GCM_H

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


class AES_256_GCM_key{
public:
    AES_256_GCM_key(const char* aad);
    ~AES_256_GCM_key();

    void genIV();

    void encrypt(const unsigned char* plaintext, unsigned char* ciphertext, int length);
    void decrypt(const unsigned char* ciphertext, unsigned char* plaintext, int length);
   
    const unsigned char* get_tag();
    const unsigned char* get_key();
    const unsigned char* get_iv();

    static constexpr int get_taglen(){
        return TAGLEN;
    }
    static constexpr int get_keylen(){
        return KEYLEN;
    }
    static constexpr int get_ivlen(){
        return IVLEN;
    }

private:
    static constexpr size_t KEYLEN = 32;
    static constexpr size_t TAGLEN = 16;
    static constexpr size_t IVLEN = 12;
    unsigned char key[KEYLEN];
    unsigned char iv[IVLEN];
    unsigned char tag[TAGLEN];
    const unsigned char* aad;
};






/*
int genRSApair(size_t byteKeySize, EVP_PKEY*);
int readRSApairPEM(FILE* priv, FILE* pub, EVP_PKEY**);
int writeRSApairPEM(FILE* priv, FILE* pub, EVP_PKEY*);
int readRSApairDER(FILE* priv, FILE* pub, EVP_PKEY**);
int writeRSApairDER(FILE* priv, FILE* pub, EVP_PKEY*);
int encryptRSA(EVP_PKEY*, char* in, size_t in_len, char* out, size_t out_len);
int decryptRSA(EVP_PKEY*, char* in, size_t in_len, char* out, size_t out_len);

int genAES(kkk
int genIV(*/

#endif
