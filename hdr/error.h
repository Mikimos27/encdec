#ifndef ENCDEC_ERROR_H
#define ENCDEC_ERROR_H
#define OPENSSL_API_COMPAT 0x30500010

#include <cstddef>

enum ErrorType{
    None = 0,
    PemError,
    FileError,
    NoPrivate,
    NoPublic,
    ExtractionError,
    SameIV,
    EncryptionError,
    DecryptionError,
    BadSig,
    SiggenError,
    KeyDerivationError,
    BadInput,
    KeygenError,
    OSSLError
};

template<typename T>
bool is_zero(T* array, std::size_t size){
    for(std::size_t i = 0; i < size; i++){
        if(array[i] != 0) return false;
    }
    return true;
}

#endif
