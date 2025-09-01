#ifndef ENCDEC_ERROR_H
#define ENCDEC_ERROR_H
#define OPENSSL_API_COMPAT 0x30500010

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

#endif
