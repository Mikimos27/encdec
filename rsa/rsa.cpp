#include "rsa.h"


RSA_keys::RSA_keys(){
    prv = EVP_PKEY_new();
    pub = EVP_PKEY_new();
}
RSA_keys::~RSA_keys(){
    if(prv != NULL) EVP_PKEY_free(prv);
    if(pub != NULL) EVP_PKEY_free(pub);
}

void RSA_keys::load_pubPEM(const char* filepath, const std::string& passwd){

}
void RSA_keys::load_prvPEM(const char* filepath, const std::string& passwd){

}
void RSA_keys::load_pubDER(const char* filepath, const std::string& passwd){

}
void RSA_keys::load_prvDER(const char* filepath, const std::string& passwd){

}


void RSA_keys::write_pubPEM(const char* filepath, const std::string& passwd){

}
void RSA_keys::write_prvPEM(const char* filepath, const std::string& passwd){

}
void RSA_keys::write_pubDER(const char* filepath, const std::string& passwd){

}
void RSA_keys::write_prvDER(const char* filepath, const std::string& passwd){

}

void RSA_keys::set_key(EVP_PKEY** keys){

}
void RSA_keys::get_key(EVP_PKEY** keys){

}


void RSA_keys::gen_key_pair(int keysize);
