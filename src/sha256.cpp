#include "../hdr/sha256.h"

std::expected<std::array<unsigned char, 32>, ErrorType> calc_sha256(unsigned char* msg, int msglen){
    EVP_MD* md = nullptr;
    EVP_MD_CTX* ctx = nullptr;
    std::array<unsigned char, 32> digest = {0};
    unsigned char out[32];

    auto err = [&]() -> ErrorType{
        ctx = EVP_MD_CTX_new();
        if(!ctx) return OSSLError;
        md = EVP_MD_fetch(NULL, "SHA256", NULL);
        if(!md) return OSSLError;
        if(!EVP_DigestInit_ex(ctx, md, NULL)) return OSSLError;
        if(!EVP_DigestUpdate(ctx, msg, msglen)) return BadInput;
        if(!EVP_DigestFinal_ex(ctx, out, NULL)) return KeygenError;
        return None;
    }();
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);

    if(err) return std::unexpected(err);
    for(size_t i = 0; i < 32; i++) digest[i] = out[i];
    return digest;
}
