#include "../hdr/dh.h"
extern "C"{
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/params.h>
#include <openssl/kdf.h>
#include <openssl/err.h>

#include <openssl/pem.h>
}
#include <cstring>
#include <cstdio>
#include <iostream>

using std::size_t;

DH_protocol::DH_protocol() 
    : keypair(nullptr), secret(nullptr), slen(0) {}
DH_protocol::~DH_protocol(){
    if(keypair) EVP_PKEY_free(keypair);
    keypair = nullptr;
    _clear_secret();
    ERR_print_errors_fp(stderr);
}


ErrorType DH_protocol::gen_key(){
    EVP_PKEY_CTX* pctx = nullptr, *kctx = nullptr; 
    EVP_PKEY* params = nullptr;
    EVP_PKEY_free(keypair);
    keypair = nullptr;
    auto err = [&]() -> ErrorType{
        kctx = EVP_PKEY_CTX_new_from_name(NULL, "X25519", NULL);
        /*
        if(!pctx || !EVP_PKEY_paramgen_init(pctx)){
            std::cerr << "DH can't init gen params\n";
            break;
        }
        char group[] = DH_GROUP;
        OSSL_PARAM params_arr[2] = {
            OSSL_PARAM_construct_utf8_string("group", group, 0),
            OSSL_PARAM_construct_end()
        };
        if(!EVP_PKEY_CTX_set_params(pctx, params_arr)){
            std::cerr << "DH can't set params\n";
            break;
        }
        if(!EVP_PKEY_paramgen(pctx, &params)){
            std::cerr << "DH can't gen params\n";
            break;
        }

        kctx = EVP_PKEY_CTX_new(params, NULL);
        */
        if(!kctx){
            std::cerr << "DH context failed\n";
            return OSSLError;
        }
        if(!EVP_PKEY_keygen_init(kctx)){
            std::cerr << "DH can't init keygen\n";
            return KeygenError;
        }
        if(!EVP_PKEY_keygen(kctx, &keypair)){
            std::cerr << "DH can't keygen\n";
            return KeygenError;
        }
        return None;
    }();
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(params);
    return err;
}


ErrorType DH_protocol::gen_secret(EVP_PKEY* peer){
    EVP_PKEY_CTX* dctx = nullptr; 
    size_t len = 0;

    _clear_secret();

    auto err = [&]() -> ErrorType{
        dctx = EVP_PKEY_CTX_new(this->keypair, NULL);
        if(!dctx){
            std::cerr << "DH context failed\n";
            return OSSLError;
        }
        if(!EVP_PKEY_derive_init(dctx)){
            std::cerr << "DH can't init derive\n";
            return KeygenError;
        }
        if(!EVP_PKEY_derive_set_peer(dctx, peer)){
            std::cerr << "DH can't set peer\n";
            return KeygenError;
        }
        if(!EVP_PKEY_derive(dctx, NULL, &len)){
            std::cerr << "DH can't get secerr len\n";
            return KeygenError;
        }
        secret = (unsigned char*)OPENSSL_malloc(len);
        if(!secret){
            std::cout << "OSSL malloc failed\n";
            return OSSLError;
        }
        if(!secret || !EVP_PKEY_derive(dctx, secret, &len)){
            std::cerr << "DH can't derive secret\n";
            return KeygenError;
        }
        
        slen = len;
        return None;
    }();

    EVP_PKEY_CTX_free(dctx);
    return err;
}

std::expected<AES_GCM, ErrorType> DH_protocol::gen_aes(const unsigned char* salt, size_t saltlen, char* aad){
    EVP_KDF* kdf = nullptr;
    EVP_KDF_CTX* ctx = nullptr;
    unsigned char* derived_key = nullptr;

    auto err = [&]() -> ErrorType{
        derived_key = (unsigned char*)OPENSSL_malloc(AES_GCM::KEYLEN);
        if(!derived_key){
            std::cerr << "OPENSSL_malloc failed (gen_aes)\n";
            return OSSLError;
        }
        kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
        ctx = EVP_KDF_CTX_new(kdf);
        if(!ctx){
            std::cerr << "Can't get HKDF ctx\n";
            return OSSLError;
        }
        const char* info = "ChaCha20-Poly1305";
        char sha256_text[] = "SHA256";
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string("digest", sha256_text, 0),
            OSSL_PARAM_construct_octet_string("salt", (void*)salt, saltlen),
            OSSL_PARAM_construct_octet_string("key", (void*)secret, slen),
            OSSL_PARAM_construct_octet_string("info", (void*)info, std::strlen(info)),
            OSSL_PARAM_construct_end()
        };
        if(!EVP_KDF_derive(ctx, derived_key, AES_GCM::KEYLEN, params)){
            std::cerr << "Can't HKDF derive aes key\n";
            return KeygenError;
        }

        return None;
    }();
    EVP_KDF_free(kdf);
    EVP_KDF_CTX_free(ctx);
    if(err != None) return std::unexpected(err);

    AES_GCM ret(derived_key, aad);

    OPENSSL_cleanse(derived_key, AES_GCM::KEYLEN);
    OPENSSL_free(derived_key);

    return ret;
}

ErrorType DH_protocol::extract_pub(EVP_PKEY** pub){
    if (!keypair)
        return NoPrivate;

    EVP_PKEY *pubkey = nullptr;
    OSSL_PARAM *params = nullptr;
    EVP_PKEY_CTX *ctx_export = nullptr;
    EVP_PKEY_CTX *ctx_import = nullptr;

    auto err = [&]() -> ErrorType{
        // Export the public components from the original key
        ctx_export = EVP_PKEY_CTX_new_from_pkey(NULL, keypair, NULL);
        if (!ctx_export){
            std::cerr << "Ctx export failed\n";
            return OSSLError;
        }

        if (EVP_PKEY_todata(keypair, EVP_PKEY_PUBLIC_KEY, &params) <= 0){
            std::cerr << "Todata failed\n";
            return ExtractionError;
        }

        // Import only the public components into a new EVP_PKEY
        ctx_import = EVP_PKEY_CTX_new_from_name(NULL, "X25519", NULL);  // or EC, etc.
        if (!ctx_import){
            std::cerr << "Ctx failed\n";
            return OSSLError;
        }

        if (EVP_PKEY_fromdata_init(ctx_import) <= 0){
            std::cerr << "Fromdata failed\n";
            return ExtractionError;
        }

        if (EVP_PKEY_fromdata(ctx_import, &pubkey, EVP_PKEY_PUBLIC_KEY, params) <= 0){
            pubkey = NULL;  // failed
            std::cerr << "Extraction failed\n";
            return ExtractionError;
        }
        return None;
    }();

    EVP_PKEY_CTX_free(ctx_export);
    EVP_PKEY_CTX_free(ctx_import);
    OSSL_PARAM_free(params);  // always free exported parameters
    EVP_PKEY_free(*pub);
    *pub = pubkey;
    pubkey = nullptr;
    return err;
}

void DH_protocol::_clear_secret(){
    if(secret) {
        OPENSSL_cleanse(secret, slen);
        OPENSSL_free(secret);
        secret = nullptr;
    }
    slen = 0;
}
