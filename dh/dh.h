#define OPENSSL_API_COMPAT 0x30500010
#ifndef DH_H
#define DH_H
#define DH_GROUP "ffdhe2048"

#include <cstddef>
#include "../aes/aes.h"

class DH_protocol{
    using uchar_p = unsigned char*;
    using std::size_t;
public:

    DH_protocol();
    ~DH_protocol();

    void gen_secret(const EVP_PKEY** local, const EVP_PKEY** peer);
    AES_GCM gen_aes();

private:
    uchar_p secret;
    size_t slen;
};

#endif
