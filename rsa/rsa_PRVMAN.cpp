void RSA_keys::load_prvPEM(const char* filepath, const char* passwd){

    std::FILE* fp = nullptr;
    fp = std::fopen(filepath, "r");
    if(fp == NULL){
        throw std::invalid_argument("Can't open file");
    }

    if(passwd){
        PEM_read_PrivateKey_ex(fp, &this->prv, NULL, (unsigned char*)passwd, NULL, NULL);
    }
    else PEM_read_PrivateKey_ex(fp, &this->prv, NULL, NULL, NULL, NULL);


    std::fclose(fp);
    this->pub = _extract_pub(this->prv);
}

void RSA_keys::write_prvPEM(const char* filepath, const char* passwd){
    std::FILE* fp = nullptr;
    fp = std::fopen(filepath, "w");
    if(fp == NULL){
        throw std::invalid_argument("Can't open file");
    }
    EVP_CIPHER* cipher = nullptr;
    if(passwd){
        cipher = EVP_CIPHER_fetch(NULL, "AES-256-CBC", NULL);
        PEM_write_PrivateKey_ex(fp, this->prv, cipher, (unsigned char*)passwd, std::strlen(passwd), NULL, NULL, NULL, NULL);
        EVP_CIPHER_free(cipher);
    }
    else PEM_write_PrivateKey_ex(fp, this->prv, NULL, NULL, 0, NULL, NULL, NULL, NULL);


    std::fclose(fp);
}
void RSA_keys::load_prvDER(const char* filepath, const char* passwd){
    std::FILE* fp = nullptr;
    fp = std::fopen(filepath, "r");
    if(fp == NULL){
        throw std::invalid_argument("Can't open file");
    }

}

void RSA_keys::write_prvDER(const char* filepath, const char* passwd){
    std::FILE* fp = nullptr;
    fp = std::fopen(filepath, "w");
    if(fp == NULL){
        throw std::invalid_argument("Bad filepath");
    }

}

void RSA_keys::write_prv_to(std::FILE* const fp, const char* const passwd){
    EVP_CIPHER* cipher = nullptr;
    if(!fp){
        throw std::invalid_argument("Can't open NULL file");
    }
    if(passwd){
        cipher = EVP_CIPHER_fetch(NULL, "AES-256-CBC", NULL);
        PEM_write_PrivateKey_ex(fp, this->prv, cipher, (unsigned char*)passwd, std::strlen(passwd), NULL, NULL, NULL, NULL);
        EVP_CIPHER_free(cipher);
    }
    else PEM_write_PrivateKey_ex(fp, this->prv, NULL, NULL, 0, NULL, NULL, NULL, NULL);
}

