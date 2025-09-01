#ifndef AES_256_GCM_H
#define AES_256_GCM_H

#include <cstddef>

class AES_256_GCM_key{
public:
    static constexpr std::size_t KEYLEN = 32;
    static constexpr std::size_t TAGLEN = 16;
    static constexpr std::size_t IVLEN = 12;



    AES_256_GCM_key(const char* aad);
    ~AES_256_GCM_key();

    void genIV();

    void encrypt(const unsigned char* plaintext, unsigned char* ciphertext, int length);
    void decrypt(const unsigned char* ciphertext, unsigned char* plaintext, int length);
   
    const unsigned char* get_tag();
    const unsigned char* get_key();
    const unsigned char* get_iv();
    const unsigned char* get_aad();

    void set_key(unsigned char (&arr)[KEYLEN]);
    void set_iv(unsigned char (&arr)[IVLEN]);

private:
    unsigned char key[KEYLEN];
    unsigned char iv[IVLEN];
    unsigned char tag[TAGLEN];
    const unsigned char* aad;
};

#endif
