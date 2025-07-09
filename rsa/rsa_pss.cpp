#include "rsa_pss.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>
#include <cstdio>

#include <string>
#include <iostream>


RSA_PSS_keys::RSA_PSS_keys(){
    prv = EVP_PKEY_new();
    pub = EVP_PKEY_new();
}
RSA_PSS_keys::~RSA_PSS_keys(){
    if(prv != NULL) EVP_PKEY_free(prv);
    if(pub != NULL) EVP_PKEY_free(pub);
}

void RSA_PSS_keys::load_pubPEM(const char* filepath, const char* passwd){

}
void RSA_PSS_keys::load_prvPEM(const char* filepath, const char* passwd){

}
void RSA_PSS_keys::load_pubDER(const char* filepath, const char* passwd){

}
void RSA_PSS_keys::load_prvDER(const char* filepath, const char* passwd){

}


void RSA_PSS_keys::write_pubPEM(const char* filepath, const char* passwd){
    std::FILE* fp = std::fopen(filepath, "w");

    PEM_write_PUBKEY_ex(fp, this->pub, NULL, passwd);

    std::fclose(fp);
}
void RSA_PSS_keys::write_prvPEM(const char* filepath, const char* passwd){

}
void RSA_PSS_keys::write_pubDER(const char* filepath, const char* passwd){

}
void RSA_PSS_keys::write_prvDER(const char* filepath, const char* passwd){

}

void RSA_PSS_keys::set_key(EVP_PKEY** keys){

}
void RSA_PSS_keys::get_key(EVP_PKEY** keys){

}


void RSA_PSS_keys::gen_key_pair(int keysize){
    if(keysize % 8){
        ///////////////////////////////////////////////////////////////
    }
    EVP_PKEY_CTX* ctx = nullptr;
    EVP_PKEY* pkey = nullptr;
    unsigned int primes = 2;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA-PSS", NULL);//change to FIPS
    do{

        if(!ctx){
            std::cerr << "EVP_PKEY_CTX_new_from_name() failed\n";
            break;
        }
        if(EVP_PKEY_keygen_init(ctx) <= 0){
            std::cerr << "EVP_PKEY_keygen_init() failed\n";
            break;
        }
        if(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, keysize) <= 0){
            std::cerr << "EVP_PKEY_CTX_set_rsa_keygen_bits() failed\n";
            break;
        }
        if(EVP_PKEY_CTX_set_rsa_keygen_primes(ctx, primes) <= 0){
            std::cerr << "EVP_PKEY_CTX_set_rsa_keygen_primes() failed\n";
            break;
        }
        if(EVP_PKEY_generate(ctx, &pkey) <= 0){
            std::cerr << "EVP_PKEY_generate() failed\n";
            break;
        }

    }while(0);

    EVP_PKEY_CTX_free(ctx);


    EVP_PKEY_free(this->prv);
    EVP_PKEY_free(this->pub);
    prv = pkey;
    pkey = nullptr;

    pub = _extract_pub(prv);
}

EVP_PKEY* RSA_PSS_keys::_extract_pub(EVP_PKEY* keypair){
    if (!keypair)
        return NULL;

    OSSL_PARAM *params = NULL;
    EVP_PKEY *pubkey = NULL;
    EVP_PKEY_CTX *ctx_export = NULL;
    EVP_PKEY_CTX *ctx_import = NULL;

    do{
        // Export the public components from the original key
        ctx_export = EVP_PKEY_CTX_new_from_pkey(NULL, keypair, NULL);
        if (!ctx_export){
            std::cerr << "Ctx export failed\n";
            break;
        }

        if (EVP_PKEY_todata(keypair, EVP_PKEY_PUBLIC_KEY, &params) <= 0){
            std::cerr << "Todata failed\n";
            break;
        }

        // Import only the public components into a new EVP_PKEY
        ctx_import = EVP_PKEY_CTX_new_from_name(NULL, "RSA-PSS", NULL);  // or EC, etc.
        if (!ctx_import){
            std::cerr << "Ctx failed\n";
            break;
        }

        if (EVP_PKEY_fromdata_init(ctx_import) <= 0){
            std::cerr << "Fromdata failed\n";
            break;
        }

        if (EVP_PKEY_fromdata(ctx_import, &pubkey, EVP_PKEY_PUBLIC_KEY, params) <= 0){
            pubkey = NULL;  // failed
            std::cerr << "Extraction failed\n";
            break;
        }
    }while(0);

    EVP_PKEY_CTX_free(ctx_export);
    EVP_PKEY_CTX_free(ctx_import);
    OSSL_PARAM_free(params);  // always free exported parameters
    return pubkey;
}
