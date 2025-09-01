#define OPENSSL_API_COMPAT 0x30500010

#ifndef AES_256_GCM_H
#define AES_256_GCM_H

#include <cstddef>
#include "error.h"

class AES_GCM{
public:
    static constexpr std::size_t KEYLEN = 32;
    static constexpr std::size_t TAGLEN = 16;
    static constexpr std::size_t IVLEN = 12;


    AES_GCM(const unsigned char* key, const char* aad);
    AES_GCM(const char* aad);
    AES_GCM(const AES_GCM& other);
    AES_GCM(AES_GCM&& other);
    ~AES_GCM();

    ErrorType gen_key();
    ErrorType genIV();

    struct enc_ret{
        const unsigned char* const iv;
        const unsigned char* const tag;
        ErrorType err;

        operator bool() const { return err == ErrorType::None ? false : true; }
    };

    enc_ret encrypt(const unsigned char* plaintext, unsigned char* ciphertext, int length);
    ErrorType decrypt(const unsigned char* ciphertext, unsigned char* plaintext, int length);
   
    const unsigned char* get_tag();
    const unsigned char* get_key();
    const unsigned char* get_iv();
    const char* get_aad();

    ErrorType set_aad(const char* arr);

    ErrorType set_key(const unsigned char (&arr)[KEYLEN]);
    ErrorType set_iv(const unsigned char (&arr)[IVLEN]);

private:
    unsigned char key[KEYLEN];
    unsigned char iv[IVLEN];
    unsigned char tag[TAGLEN];
    char* aad;

    bool sameIV;
};

#endif
