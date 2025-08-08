#define OPENSSL_API_COMPAT 0x30500010
#ifndef DH_H
#define DH_H
#define DH_GROUP "ffdhe2048"

#include <openssl/evp.h>
#include <cstddef>
#include "../aes/aes.h"

class DH_protocol{
public:

    DH_protocol();
    ~DH_protocol();

    void gen_key();
    int gen_secret(EVP_PKEY* peer);
    AES_GCM gen_aes(const unsigned char* salt, size_t saltlen, size_t key_len);
    int extract_pub(EVP_PKEY** pub);

private:

    void _clear_secret();

    EVP_PKEY* keypair;
    unsigned char* secret;
    std::size_t slen;
};

#endif
