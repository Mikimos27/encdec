#include "../hdr/helper.h"

const char* E2s(ErrorType err){
    switch(err){
        CASE_RETURN_STRING(None);
        CASE_RETURN_STRING(PemError);
        CASE_RETURN_STRING(FileError);
        CASE_RETURN_STRING(NoPrivate);
        CASE_RETURN_STRING(NoPublic);
        CASE_RETURN_STRING(ExtractionError);
        CASE_RETURN_STRING(SameIV);
        CASE_RETURN_STRING(EncryptionError);
        CASE_RETURN_STRING(DecryptionError);
        CASE_RETURN_STRING(BadSig);
        CASE_RETURN_STRING(SiggenError);
        CASE_RETURN_STRING(KeyDerivationError);
        CASE_RETURN_STRING(BadInput);
        CASE_RETURN_STRING(KeygenError);
        CASE_RETURN_STRING(OSSLError);
    }
    return "BAD_ERR_TYPE";
}

evp_pkey::evp_pkey()
: key(nullptr) {}
evp_pkey::evp_pkey(EVP_PKEY** pkey) noexcept
: key(*pkey) {
    *pkey = nullptr;
}
evp_pkey::evp_pkey(const evp_pkey& pkey){
    key = EVP_PKEY_dup(pkey.key);
}
evp_pkey::evp_pkey(evp_pkey&& pkey) noexcept {
    key = pkey.key;
    pkey.key = nullptr;
}
evp_pkey::~evp_pkey(){
    EVP_PKEY_free(key);
    key = nullptr;
}


std::vector<unsigned char> EVP2RAW_prv(EVP_PKEY* key){
    if(key == nullptr) return {};
    size_t len = 0;
    if(!EVP_PKEY_get_raw_private_key(key, NULL, &len)) return {};
    unsigned char* buff = (unsigned char*)OPENSSL_malloc(len);
    if(!buff) return {};

    if(!EVP_PKEY_get_raw_private_key(key, buff, &len)) return {};

    std::vector<unsigned char> ret;
    ret.resize(len);
    for(size_t i = 0; i < len; i++) ret.at(i) = buff[i];
    OPENSSL_free(buff);

    return ret;
}
std::vector<unsigned char> EVP2RAW_pub(EVP_PKEY* key){
    if(key == nullptr) return {};
    size_t len = 0;
    if(!EVP_PKEY_get_raw_public_key(key, NULL, &len)) return {};
    unsigned char* buff = (unsigned char*)OPENSSL_malloc(len);
    if(!buff) return {};

    if(!EVP_PKEY_get_raw_public_key(key, buff, &len)) return {};

    std::vector<unsigned char> ret;
    ret.resize(len);
    for(size_t i = 0; i < len; i++) ret.at(i) = buff[i];
    OPENSSL_free(buff);

    return ret;
}

evp_pkey RAW2EVP_prv(const std::vector<unsigned char>& raw, const char* type){
    evp_pkey key;
    key.key = EVP_PKEY_new_raw_private_key_ex(NULL, type, NULL, raw.data(), raw.size());
    return key;
}
evp_pkey RAW2EVP_pub(const std::vector<unsigned char>& raw, const char* type){
    evp_pkey key;
    key.key = EVP_PKEY_new_raw_public_key_ex(NULL, type, NULL, raw.data(), raw.size());
    return key;
}
