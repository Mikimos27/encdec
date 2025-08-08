#define OPENSSL_API_COMPAT 0x30500010

#ifndef AES_256_GCM_H
#define AES_256_GCM_H

#include <cstddef>

class AES_GCM{
public:
    static constexpr std::size_t KEYLEN = 32;
    static constexpr std::size_t TAGLEN = 16;
    static constexpr std::size_t IVLEN = 12;


    AES_GCM();

    AES_GCM(unsigned char* key, const char* aad);
    AES_GCM(const char* aad);
    AES_GCM(const AES_GCM& other);
    AES_GCM(AES_GCM&& other);
    ~AES_GCM();

    void gen_key();
    void genIV();

    void encrypt(const unsigned char* plaintext, unsigned char* ciphertext, int length);
    void decrypt(const unsigned char* ciphertext, unsigned char* plaintext, int length);
   
    const unsigned char* get_tag();
    const unsigned char* get_key();
    const unsigned char* get_iv();
    const char* get_aad();

    void set_aad();//!!!!!!!!!!!!!!!!

    void set_key(unsigned char (&arr)[KEYLEN]);
    void set_iv(unsigned char (&arr)[IVLEN]);

private:
    unsigned char key[KEYLEN];
    unsigned char iv[IVLEN];
    unsigned char tag[TAGLEN];
    char* aad;
    bool valid = true;
};

#endif
