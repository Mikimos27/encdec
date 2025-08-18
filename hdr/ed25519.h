#define OPENSSL_API_COMPAT 0x30500010

#ifndef ED25519_H
#define ED25519_H
extern "C"{
#include <openssl/evp.h>
}
#include <string>
#include <cstdio>
#include <cstddef>

#include "error.h"

class Ed25519{
public:
    Ed25519();
    ~Ed25519();

    ErrorType load_pubPEM(const char* filepath);
    ErrorType write_pubPEM(const char* filepath);
    ErrorType load_pubDER(const char* filepath);
    ErrorType write_pubDER(const char* filepath);
    ErrorType write_pub_to(std::FILE* const fp);

    ErrorType load_prvPEM(const char* filepath, char* passwd);      //
    ErrorType write_prvPEM(const char* filepath, char* passwd);     //
    ErrorType load_prvDER(const char* filepath, char* passwd);      // they eat passwors (set to zero) 
    ErrorType write_prvDER(const char* filepath, char* passwd);     //
    ErrorType write_prv_to(std::FILE* const fp, char* passwd);      //

    ErrorType set_key_prv(EVP_PKEY* keys);
    const EVP_PKEY* const get_key_prv();

    ErrorType set_key_pub(EVP_PKEY* keys);
    const EVP_PKEY* const get_key_pub();

    ErrorType gen_key_pair(int keysize);
    

    ErrorType sign(const unsigned char* msg, int msglen);
    ErrorType verify(const unsigned char* msg, int msglen, const unsigned char* signature, int siglen);

    const unsigned char* const get_out_buff();
    const std::size_t get_out_size();
    const std::size_t get_ciph_size();

private:
    
    ErrorType _extract_pub(EVP_PKEY* pkey, EVP_PKEY** pub);
    void _clear_buff();
    void _free_key(EVP_PKEY** pkey);


    EVP_PKEY* prv;
    EVP_PKEY* pub;
    int keysize;

    unsigned char* out_buff;
    std::size_t out_size;
};

#endif
