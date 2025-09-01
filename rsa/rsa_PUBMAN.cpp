void RSA_keys::load_pubPEM(const char* filepath){
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

void RSA_keys::write_pubPEM(const char* filepath){
    std::FILE* fp = std::fopen(filepath, "w");

    if(!fp) std::invalid_argument("Bad filepath");

    if(!PEM_write_PUBKEY(fp, this->pub)){
        throw std::invalid_argument("Can't write pub to PEM\n");
    }

    std::fclose(fp);
}

void RSA_keys::load_pubDER(const char* filepath){
    std::FILE* fp = nullptr;
    fp = std::fopen(filepath, "r");
    if(fp == NULL){
        throw std::invalid_argument("Can't open file");
    }


}


void RSA_keys::write_pubDER(const char* filepath){
    std::FILE* fp = nullptr;
    fp = std::fopen(filepath, "w");
    if(fp == NULL){
        throw std::invalid_argument("Bad filepath");
    }


}

void RSA_keys::write_pub_to(std::FILE* const fp){
    if(fp == NULL){
        throw std::invalid_argument("Can't open file");
    }

    PEM_write_PUBKEY_ex(fp, this->pub, NULL, NULL);
}

////////////////////Problem vvvvvvvvvvvvvv
int RSA_keys::_extract_pub(EVP_PKEY* keypair, EVP_PKEY** pub){
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
        ctx_import = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);  // or EC, etc.
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
////////////////////Problem ^^^^^^^^^^^^^^
/*
EVP_PKEY* RSA_keys::_extract_pub(EVP_PKEY* keypair){
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
