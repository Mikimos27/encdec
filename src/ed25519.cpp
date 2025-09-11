#include "../hdr/ed25519.h"
extern "C"{
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>
#include <cstdio>
#include <cstring>
}

#include <string>
#include <iostream>
#include <exception>

Ed25519::Ed25519(){
    this->prv = nullptr;
    this->pub = nullptr;
    out_buff = nullptr;
    out_size = 0;
}
Ed25519::~Ed25519(){
    if(prv != nullptr) _free_key(&prv);
    if(pub != nullptr) _free_key(&pub);
    _clear_buff();
    ERR_print_errors_fp(stderr);
}


ErrorType Ed25519::set_key_prv(EVP_PKEY* keys){
    auto newkey = EVP_PKEY_dup(keys);
    if(!newkey) return KeygenError;
    _free_key(&prv);
    prv = newkey;
    newkey = nullptr;

    _clear_buff();
    if(_extract_pub(prv, &pub)) {
        std::cerr << "Ed25519::set_key_prv _extract_pub error\n";
        return ExtractionError;
    }
    return None;
}
EVP_PKEY* Ed25519::get_key_prv(){
    return prv;
}


ErrorType Ed25519::set_raw_prv(unsigned char (&keys)[ED25519_KEY]){
    EVP_PKEY* new_prv = nullptr;
    EVP_PKEY* new_pub = nullptr;
    new_prv = EVP_PKEY_new_raw_private_key_ex(NULL, "Ed25519", NULL, keys, ED25519_KEY);
    if(!new_prv) return KeygenError;
    if(_extract_pub(new_prv, &new_pub)) return ExtractionError;

    _free_key(&this->prv);
    _free_key(&this->pub);
    _clear_buff();

    this->prv = new_prv;
    new_prv = nullptr;
    this->pub = new_pub;
    new_pub = nullptr;

    return None;
}

ErrorType Ed25519::get_raw_prv(){
    if(this->prv == nullptr) return NoPrivate;
    size_t len = 0;
    if(!EVP_PKEY_get_raw_private_key(this->prv, NULL, &len)) return NoPrivate;
    unsigned char* buff = (unsigned char*)OPENSSL_malloc(len);
    if(!buff) return OSSLError;

    if(!EVP_PKEY_get_raw_private_key(this->prv, buff, &len)) return NoPrivate;

    _clear_buff();
    out_buff = buff;
    out_size = len;

    return None;
}

ErrorType Ed25519::set_key_pub(EVP_PKEY* keys){
    auto newkey = EVP_PKEY_dup(keys);
    if(!newkey) return KeygenError;
    _free_key(&pub);
    _free_key(&prv);
    prv = nullptr;
    pub = newkey;
    newkey = nullptr;

    _clear_buff();

    return None;
}
EVP_PKEY* Ed25519::get_key_pub(){
    return pub;
}


ErrorType Ed25519::set_raw_pub(unsigned char (&keys)[ED25519_KEY]){
    EVP_PKEY* new_pub = nullptr;
    new_pub = EVP_PKEY_new_raw_public_key_ex(NULL, "Ed25519", NULL, keys, ED25519_KEY);
    if(!new_pub) return KeygenError;

    _free_key(&this->prv);
    _free_key(&this->pub);
    _clear_buff();

    this->prv = nullptr;
    this->pub = new_pub;
    new_pub = nullptr;

    return None;
}

ErrorType Ed25519::get_raw_pub(){
    if(this->pub == nullptr) return NoPublic;
    size_t len = 0;
    if(!EVP_PKEY_get_raw_public_key(this->pub, NULL, &len)) return NoPublic;
    unsigned char* buff = (unsigned char*)OPENSSL_malloc(len);
    if(!buff) return OSSLError;

    if(!EVP_PKEY_get_raw_public_key(this->pub, buff, &len)) return NoPublic;

    _clear_buff();
    out_buff = buff;
    out_size = len;

    return None;
}


ErrorType Ed25519::gen_key_pair(){
    _clear_buff();
    EVP_PKEY_CTX* ctx = nullptr;
    EVP_PKEY* pkey = nullptr;
    //unsigned int primes = 2;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "Ed25519", NULL);//change to FIPS
    //ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);//change to FIPS
    auto err = [&]() -> ErrorType {
        if(!ctx){
            std::cerr << "EVP_PKEY_CTX_new_from_name() failed\n";
            return OSSLError;
        }
        if(EVP_PKEY_keygen_init(ctx) <= 0){
            std::cerr << "EVP_PKEY_keygen_init() failed\n";
            return KeygenError;
        }
        /*
        if(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, keysize) <= 0){
            std::cerr << "EVP_PKEY_CTX_set_rsa_keygen_bits() failed\n";
            break;
        }
        if(EVP_PKEY_CTX_set_rsa_keygen_primes(ctx, primes) <= 0){
            std::cerr << "EVP_PKEY_CTX_set_rsa_keygen_primes() failed\n";
            break;
        }
        */
        if(EVP_PKEY_generate(ctx, &pkey) <= 0){
            std::cerr << "EVP_PKEY_generate() failed\n";
            return KeygenError;
        }
        return None;
    }();

    EVP_PKEY_CTX_free(ctx);
    if(err) return err;


    if(this->prv) _free_key(&this->prv);
    if(this->pub) _free_key(&this->pub);
    prv = pkey;
    pkey = nullptr;


    if(_extract_pub(prv, &pub)) throw std::invalid_argument("Can't extract pub key\n");
    if(!pub) throw std::invalid_argument("BAD in genkey\n");

    return err;
}


ErrorType Ed25519::_extract_pub(EVP_PKEY* keypair, EVP_PKEY** pub){
    if (!keypair)
        return ExtractionError;

    EVP_PKEY *pubkey = nullptr;
    OSSL_PARAM *params = nullptr;
    EVP_PKEY_CTX *ctx_export = nullptr;
    EVP_PKEY_CTX *ctx_import = nullptr;

    auto err = [&]() -> ErrorType {
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
        ctx_import = EVP_PKEY_CTX_new_from_name(NULL, "Ed25519", NULL);  // or EC, etc.
        if (!ctx_import){
            std::cerr << "Ctx failed\n";
            return OSSLError;
        }

        if (EVP_PKEY_fromdata_init(ctx_import) <= 0){
            std::cerr << "Fromdata failed\n";
            return ExtractionError;
        }

        if (EVP_PKEY_fromdata(ctx_import, &pubkey, EVP_PKEY_PUBLIC_KEY, params) <= 0){
            std::cerr << "Extraction failed\n";
            return ExtractionError;
        }
        return None;
    }();

    EVP_PKEY_CTX_free(ctx_export);
    EVP_PKEY_CTX_free(ctx_import);
    OSSL_PARAM_free(params);  // always free exported parameters

    if(err) {
        pubkey = nullptr;
        return err;
    }

    if(*pub) _free_key(pub);
    *pub = pubkey;
    pubkey = nullptr;
    return err;
}
/*
EVP_PKEY* Ed25519::_extract_pub(EVP_PKEY* keypair){
    if (!keypair)
        return nullptr;
    EVP_PKEY *pubkey = nullptr;
    BIO* bio = BIO_new(BIO_s_mem());
    if(!PEM_read_bio_PUBKEY(bio, &keypair)) throw std::invalid_argument("BAD1\n");
    if(!PEM_write_bio_PUBKEY(bio, pubkey)) throw std::invalid_argument("BAD2\n");
    PEM_write_PUBKEY(stdout, pubkey);



    BIO_free(bio);
    return pubkey;
}
*/

const unsigned char* const Ed25519::get_out_buff(){
    return out_buff;
}
const std::size_t Ed25519::get_out_size(){
    return this->out_size;
}
const std::size_t Ed25519::get_ciph_size(){
    return this->pub == nullptr ? 0 : EVP_PKEY_get_size(this->pub);//constexpr to 64??????
}

void Ed25519::_clear_buff(){
    if(out_buff){
        OPENSSL_cleanse(out_buff, out_size);
        OPENSSL_free(out_buff);
    }
    out_buff = nullptr;
    out_size = 0;
}

void Ed25519::_free_key(EVP_PKEY** pkey){
    //static int free_count = 0;
    if(*pkey){
        EVP_PKEY_free(*pkey);
        *pkey = nullptr;
        //free_count++;
        //std::cout << free_count << '\n';
    }
}


//PRV methods

ErrorType Ed25519::load_prvPEM(const char* filepath, char* passwd){

    std::FILE* fp = nullptr;
    fp = std::fopen(filepath, "r");
    if(!fp){
        return FileError;
    }
    EVP_PKEY* newkey = nullptr;

    if(!PEM_read_PrivateKey_ex(fp, &newkey, NULL, (unsigned char*)passwd, NULL, NULL)){
        std::fclose(fp);
        return PemError;
    }
    if(passwd) OPENSSL_cleanse((void*)passwd, std::strlen(passwd));


    if(this->prv) _free_key(&this->prv);
    this->prv = newkey;


    std::fclose(fp);
    if(_extract_pub(this->prv, &this->pub)) {
        std::cerr << "Ed25519::load_prvPEM _extract_pub error\n";
        return ExtractionError;
    }

    return None;
}

ErrorType Ed25519::write_prvPEM(const char* filepath, char* passwd){
    std::FILE* fp = nullptr;
    fp = std::fopen(filepath, "w");
    if(!fp){
        return FileError;
    }
    EVP_CIPHER* cipher = nullptr;
    if(passwd){
        cipher = EVP_CIPHER_fetch(NULL, "AES-256-CBC", NULL);
        if(!cipher) {
            std::fclose(fp);
            return OSSLError;
        }
        if(!PEM_write_PrivateKey_ex(fp, this->prv, cipher, (unsigned char*)passwd, std::strlen(passwd), NULL, NULL, NULL, NULL)) {
            EVP_CIPHER_free(cipher);
            std::fclose(fp);
            return PemError;
        }
        OPENSSL_cleanse((void*)passwd, std::strlen(passwd));
        EVP_CIPHER_free(cipher);
    }
    else if(!PEM_write_PrivateKey_ex(fp, this->prv, NULL, NULL, 0, NULL, NULL, NULL, NULL)) {
        std::fclose(fp);
        return PemError;
    }


    std::fclose(fp);
    return None;
}
ErrorType Ed25519::load_prvDER(const char* filepath, char* passwd){
    return FileError;
    std::FILE* fp = nullptr;
    fp = std::fopen(filepath, "r");
    if(!fp){
        throw std::invalid_argument("Can't open file");
    }
    if(passwd){
        EVP_PKEY_free(this->prv);
        this->prv = EVP_PKEY_new();
    }

}

ErrorType Ed25519::write_prvDER(const char* filepath, char* passwd){
    return FileError;
    std::FILE* fp = nullptr;
    fp = std::fopen(filepath, "w");
    if(!fp){
        throw std::invalid_argument("Bad filepath");
    }

}

ErrorType Ed25519::write_prv_to(std::FILE* const fp, char* passwd){
    EVP_CIPHER* cipher = nullptr;
    if(!fp){
        return FileError;
    }
    if(passwd){
        cipher = EVP_CIPHER_fetch(NULL, "AES-256-CBC", NULL);
        if(!cipher) {
            return OSSLError;
        }
        if(!PEM_write_PrivateKey_ex(fp, this->prv, cipher, (unsigned char*)passwd, std::strlen(passwd), NULL, NULL, NULL, NULL)) {
            EVP_CIPHER_free(cipher);
            return PemError;
        }
        OPENSSL_cleanse((void*)passwd, std::strlen(passwd));
        EVP_CIPHER_free(cipher);
    }
    else if(!PEM_write_PrivateKey_ex(fp, this->prv, NULL, NULL, 0, NULL, NULL, NULL, NULL)) return PemError;
    return None;
}

//PUB methods

ErrorType Ed25519::load_pubPEM(const char* filepath){
    std::FILE* fp = nullptr;
    fp = std::fopen(filepath, "r");
    if(this->pub) _free_key(&this->pub);
    if(!fp) return FileError;
    if(!PEM_read_PUBKEY_ex(fp, &this->pub, NULL, NULL, NULL, NULL)){
        std::fclose(fp);
        return PemError;
    }
    std::fclose(fp);
    return None;
}

ErrorType Ed25519::write_pubPEM(const char* filepath){
    std::FILE* fp = std::fopen(filepath, "w");

    if(!fp) return FileError;
    if(!PEM_write_PUBKEY(fp, this->pub)){
        std::fclose(fp);
        return PemError;
    }

    std::fclose(fp);
    return None;
}

ErrorType Ed25519::load_pubDER(const char* filepath){
    return FileError;


    std::FILE* fp = nullptr;
    fp = std::fopen(filepath, "r");
    if(fp == NULL){
        throw std::invalid_argument("Can't open file");
    }

}


ErrorType Ed25519::write_pubDER(const char* filepath){
    return FileError;


    std::FILE* fp = nullptr;
    fp = std::fopen(filepath, "w");
    if(fp == NULL){
        throw std::invalid_argument("Bad filepath");
    }

}

ErrorType Ed25519::write_pub_to(std::FILE* const fp){
    if(!fp) return FileError;
    

    if(!PEM_write_PUBKEY_ex(fp, this->pub, NULL, NULL)) return PemError;
    return None;
}



//Cryptography

ErrorType Ed25519::sign(const unsigned char* msg, int msglen){
    if(!this->prv)
        return NoPrivate;
    EVP_MD_CTX* ctx = nullptr;
    std::size_t plen = 0;

    _clear_buff();


    auto err = [&]() -> ErrorType{
        ctx = EVP_MD_CTX_new();
        if(!ctx){
            std::cerr << "Can't generate ctx for signature\n";
            return OSSLError;
        }

        if(!EVP_DigestSignInit(ctx, NULL, NULL, NULL, this->prv)){//Change to _ex for Openssl 3.0
            std::cerr << "Sig init failed\n";
            return SiggenError;
        }
        if(!EVP_DigestSign(ctx, NULL, &plen, msg, msglen)){
            std::cerr << "Sig get size failed\n";
            return SiggenError;
        }
        out_buff = (unsigned char*)OPENSSL_malloc(plen);
        if(!out_buff) return OSSLError;
        if(!EVP_DigestSign(ctx, out_buff, &plen, msg, msglen)){
            std::cerr << "Sig gen failed\n";
            return SiggenError;
        }

        out_size = plen;
        return None;
    }();

    EVP_MD_CTX_free(ctx);
    return err;
}

ErrorType Ed25519::verify(const unsigned char* msg, int msglen, const unsigned char* signature, int siglen){
    if(!this->pub) return NoPublic;
    EVP_MD_CTX* ctx = nullptr;
    auto err = [&]() -> ErrorType{
        ctx = EVP_MD_CTX_new();
        if(!ctx){
            std::cerr << "Can't generate ctx for sig ver\n";
            return OSSLError;
        }
        if(!EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, this->pub)){
            std::cerr << "Verify init failed\n";
            return OSSLError;
        }

        if(!EVP_DigestVerify(ctx, signature, siglen, msg, msglen)){
            std::cerr << "Verification failed\n";
            return BadSig;
        }
        return None;
    }();

    EVP_MD_CTX_free(ctx);
    return err;
}



