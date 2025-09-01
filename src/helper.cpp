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
