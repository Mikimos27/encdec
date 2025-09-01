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
    keysize = 0;
    out_buff = nullptr;
    out_size = 0;
}
Ed25519::~Ed25519(){
    if(prv != nullptr) _free_key(&prv);
    if(pub != nullptr) _free_key(&pub);
    keysize = 0;
    _clear_buff();
    ERR_print_errors_fp(stderr);
}


void Ed25519::set_key_prv(EVP_PKEY** keys){
    _free_key(&prv);
    prv = *keys;
    *keys = nullptr;

    keysize = EVP_PKEY_get_bits(prv);

    _clear_buff();
    if(_extract_pub(prv, &pub)) std::cerr << "Ed25519::set_key_prv _extract_pub error\n";
}
const EVP_PKEY* const Ed25519::get_key_prv(){
    return prv;
}

void Ed25519::set_key_pub(EVP_PKEY** keys){
    _free_key(&pub);
    _free_key(&prv);
    prv = nullptr;
    pub = *keys;
    *keys = nullptr;

    _clear_buff();
}
const EVP_PKEY* const Ed25519::get_key_pub(){
    return pub;
}

int Ed25519::gen_key_pair(int keysize){
    //if(keysize < 1024) throw std::logic_error("Key must be at least 1024 bits long, ideally equal or larger than 2048 bits");
    if(keysize % 8){
        std::cerr << "Key size not divisible by 8\n";
        return -1;
    }
    _clear_buff();
    EVP_PKEY_CTX* ctx = nullptr;
    EVP_PKEY* pkey = nullptr;
    //unsigned int primes = 2;

    //Problemvvvvv
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "Ed25519", NULL);//change to FIPS
    //ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);//change to FIPS
    //Problem^^^^^
    do{

        if(!ctx){
            std::cerr << "EVP_PKEY_CTX_new_from_name() failed\n";
            break;
        }
        if(EVP_PKEY_keygen_init(ctx) <= 0){
            std::cerr << "EVP_PKEY_keygen_init() failed\n";
            break;
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
            break;
        }

    }while(0);

    EVP_PKEY_CTX_free(ctx);


    if(this->prv) _free_key(&this->prv);
    if(this->pub) _free_key(&this->pub);
    prv = pkey;
    pkey = nullptr;

    if(_extract_pub(prv, &pub)) throw std::invalid_argument("Can't extract pub key\n");
    if(!pub) throw std::invalid_argument("BAD in genkey\n");
    this->keysize = keysize;

    return 0;
}


int Ed25519::_extract_pub(EVP_PKEY* keypair, EVP_PKEY** pub){
    if (!keypair)
        return 1;

    EVP_PKEY *pubkey = nullptr;
    OSSL_PARAM *params = nullptr;
    EVP_PKEY_CTX *ctx_export = nullptr;
    EVP_PKEY_CTX *ctx_import = nullptr;

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
        ctx_import = EVP_PKEY_CTX_new_from_name(NULL, "Ed25519", NULL);  // or EC, etc.
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
    if(*pub) _free_key(pub);
    *pub = pubkey;
    pubkey = nullptr;
    return 0;
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
    return this->pub == nullptr ? 0 : EVP_PKEY_get_size(this->pub);
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

void Ed25519::load_prvPEM(const char* filepath, char* passwd){

    std::FILE* fp = nullptr;
    fp = std::fopen(filepath, "r");
    if(fp == NULL){
        throw std::invalid_argument("Can't open file");
    }
    if(this->prv) _free_key(&this->prv);

    if(passwd){
        if(!PEM_read_PrivateKey_ex(fp, &this->prv, NULL, (unsigned char*)passwd, NULL, NULL)) throw std::invalid_argument("Bad decryption passphrase");
        OPENSSL_cleanse((void*)passwd, std::strlen(passwd));
    }
    else if(!PEM_read_PrivateKey_ex(fp, &this->prv, NULL, NULL, NULL, NULL)) throw std::invalid_argument("Bad decryption passphrase");



    std::fclose(fp);
    //vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
    if(_extract_pub(this->prv, &this->pub)) std::cerr << "Ed25519::load_prvPEM _extract_pub error\n";
}

void Ed25519::write_prvPEM(const char* filepath, char* passwd){
    std::FILE* fp = nullptr;
    fp = std::fopen(filepath, "w");
    if(fp == NULL){
        throw std::invalid_argument("Can't open file");
    }
    EVP_CIPHER* cipher = nullptr;
    if(passwd){
        cipher = EVP_CIPHER_fetch(NULL, "AES-256-CBC", NULL);
        PEM_write_PrivateKey_ex(fp, this->prv, cipher, (unsigned char*)passwd, std::strlen(passwd), NULL, NULL, NULL, NULL);
        OPENSSL_cleanse((void*)passwd, std::strlen(passwd));
        EVP_CIPHER_free(cipher);
    }
    else PEM_write_PrivateKey_ex(fp, this->prv, NULL, NULL, 0, NULL, NULL, NULL, NULL);


    std::fclose(fp);
}
void Ed25519::load_prvDER(const char* filepath, char* passwd){
    std::FILE* fp = nullptr;
    fp = std::fopen(filepath, "r");
    if(fp == NULL){
        throw std::invalid_argument("Can't open file");
    }
    if(passwd){
        EVP_PKEY_free(this->prv);
        this->prv = EVP_PKEY_new();

    }

}

void Ed25519::write_prvDER(const char* filepath, char* passwd){
    std::FILE* fp = nullptr;
    fp = std::fopen(filepath, "w");
    if(fp == NULL){
        throw std::invalid_argument("Bad filepath");
    }

}

void Ed25519::write_prv_to(std::FILE* const fp, char* passwd){
    EVP_CIPHER* cipher = nullptr;
    if(!fp){
        throw std::invalid_argument("Can't open NULL file");
    }
    if(passwd){
        cipher = EVP_CIPHER_fetch(NULL, "AES-256-CBC", NULL);
        PEM_write_PrivateKey_ex(fp, this->prv, cipher, (unsigned char*)passwd, std::strlen(passwd), NULL, NULL, NULL, NULL);
        OPENSSL_cleanse((void*)passwd, std::strlen(passwd));
        EVP_CIPHER_free(cipher);
    }
    else PEM_write_PrivateKey_ex(fp, this->prv, NULL, NULL, 0, NULL, NULL, NULL, NULL);
}

//PUB methods

void Ed25519::load_pubPEM(const char* filepath){
    std::FILE* fp = nullptr;
    fp = std::fopen(filepath, "r");
    if(this->pub) _free_key(&this->pub);
    if(fp == NULL){
        throw std::invalid_argument("Can't open file");
    }
    if(!PEM_read_PUBKEY_ex(fp, &this->pub, NULL, NULL, NULL, NULL)){
        throw std::invalid_argument("Can't read pub from PEM\n");
    }
    std::fclose(fp);
}

void Ed25519::write_pubPEM(const char* filepath){
    std::FILE* fp = std::fopen(filepath, "w");

    if(!fp) std::invalid_argument("Bad filepath");

    if(!PEM_write_PUBKEY(fp, this->pub)){
        throw std::invalid_argument("Can't write pub to PEM\n");
    }

    std::fclose(fp);
}

void Ed25519::load_pubDER(const char* filepath){
    std::FILE* fp = nullptr;
    fp = std::fopen(filepath, "r");
    if(fp == NULL){
        throw std::invalid_argument("Can't open file");
    }


}


void Ed25519::write_pubDER(const char* filepath){
    std::FILE* fp = nullptr;
    fp = std::fopen(filepath, "w");
    if(fp == NULL){
        throw std::invalid_argument("Bad filepath");
    }


}

void Ed25519::write_pub_to(std::FILE* const fp){
    if(fp == NULL){
        throw std::invalid_argument("Can't open file");
    }

    PEM_write_PUBKEY_ex(fp, this->pub, NULL, NULL);
}



//Cryptography

void Ed25519::sign(const unsigned char* msg, int msglen){
    if(!this->prv)
        throw std::logic_error("There is no private key set");
    EVP_MD_CTX* ctx = nullptr;
    std::size_t plen = 0;

    _clear_buff();


    do{
        ctx = EVP_MD_CTX_new();
        if(!ctx){
            std::cerr << "Can't generate ctx for signature\n";
            break;
        }

        if(!EVP_DigestSignInit(ctx, NULL, NULL, NULL, this->prv)){//Change to _ex for Openssl 3.0
            std::cerr << "Sig init failed\n";
            break;
        }
        std::cout << "Msg: " << msg << "\nMsglen = " << msglen << '\n';
        if(!EVP_DigestSign(ctx, NULL, &plen, msg, msglen)){
            std::cerr << "Sig get size failed\n";
            break;
        }
        out_buff = (unsigned char*)OPENSSL_malloc(plen);
        if(!EVP_DigestSign(ctx, out_buff, &plen, msg, msglen)){
            std::cerr << "Sig gen failed\n";
            break;
        }

        out_size = plen;

    }while(0);

    EVP_MD_CTX_free(ctx);
}

int Ed25519::verify(const unsigned char* msg, int msglen, const unsigned char* signature, int siglen){
    EVP_MD_CTX* ctx = nullptr;
    int failed = 1;
    do{
        ctx = EVP_MD_CTX_new();
        if(!ctx){
            std::cerr << "Can't generate ctx for sig ver\n";
            break;
        }
        if(!EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, this->pub)){
            std::cerr << "Verify init failed\n";
            break;
        }

        if(!EVP_DigestVerify(ctx, signature, siglen, msg, msglen)){
            std::cerr << "Verification failed\n";
            break;
        }
        failed = 0;
    }while(0);

    EVP_MD_CTX_free(ctx);
    return failed;
}



