#ifndef ENCDEC_ERROR_H
#define ENCDEC_ERROR_H

enum ErrorType{
    None = 0,
    PemError,
    FileError,
    NoPrivate,
    NoPublic,
    CantExtract,
    SameIV,
    EncryptionError,
    DecryptionError,
    BadSig,
    SigCreationError,
    KeyDerivationError
};

#endif
