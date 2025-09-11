#ifndef HELPER_H
#define HELPER_H
#include "error.h"
extern "C"{
#include <openssl/pem.h>
}
#include <vector>

#define CASE_RETURN_STRING(X) case X: return #X
template<typename T>
bool is_zero(T* array, std::size_t size){
    for(std::size_t i = 0; i < size; i++){
        if(array[i] != 0) return false;
    }
    return true;
}

const char* E2s(ErrorType err);

struct evp_pkey{
    EVP_PKEY* key;

    evp_pkey();
    evp_pkey(EVP_PKEY** key) noexcept;
    evp_pkey(const evp_pkey&);
    evp_pkey(evp_pkey&&) noexcept;
    ~evp_pkey();
};

std::vector<unsigned char> EVP2RAW_prv(EVP_PKEY*);
std::vector<unsigned char> EVP2RAW_pub(EVP_PKEY*);

evp_pkey RAW2EVP_prv(const std::vector<unsigned char>&, const char* type);
evp_pkey RAW2EVP_pub(const std::vector<unsigned char>&, const char* type);
#endif
