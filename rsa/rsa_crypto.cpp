void RSA_keys::encrypt(const unsigned char* plaintext, int msgsize){
    if(!this->pub)
        throw std::logic_error("There is no public key set");
    EVP_PKEY_CTX* ctx = nullptr;
    //OSSL_LIB_CTX* libctx = nullptr;
    std::size_t clen = 0;

    _clear_buff();
    EVP_MD* md = nullptr;

    do{
        //libctx = OSSL_LIB_CTX_new();
        //if(!libctx){
        //    std::cerr << "OSSL_LIB_CTX new fail\n";
        //    break;
        //}
        ctx = EVP_PKEY_CTX_new_from_pkey(NULL, this->pub, NULL);//PARAMS///////////////////////////////
        if(!ctx){
            std::cerr << "Can't generate ctx for encryption\n";
            break;
        }
        if(!EVP_PKEY_encrypt_init_ex(ctx, NULL)){
            std::cerr << "Encrypt init failed\n";
            break;
        }


        md = EVP_MD_fetch(NULL, "SHA256", NULL);
        if(!md){
            std::cerr << "SHA256 fetch fail\n";
            break;
        }

        if (!EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING)){
            std::cerr << "Encryption padding set fail\n";
            break;
        }


        if(!EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md)){
            std::cerr << "OAEP hash set fail\n";
            break;
        }
        if(!EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md)){
            std::cerr << "MGF1 hash set fail\n";
            break;
        }


        if(!EVP_PKEY_encrypt(ctx, NULL, &clen, plaintext, msgsize)){
            std::cerr << "Encryption length check failed\n";
            break;
        }
        out_buff = (unsigned char*)OPENSSL_malloc(clen);
        if(!EVP_PKEY_encrypt(ctx, out_buff, &clen, plaintext, msgsize)){
            std::cerr << "Encrypt failed\n";
            break;
        }

        out_size = clen;

    }while(0);

    ERR_print_errors_fp(stderr);
    EVP_PKEY_CTX_free(ctx);
    EVP_MD_free(md);
    //OSSL_LIB_CTX_free(libctx);
}

void RSA_keys::decrypt(const unsigned char* ciphertext){
    if(!this->prv)
        throw std::logic_error("There is no private key set");
    EVP_PKEY_CTX* ctx = nullptr;
    std::size_t plen = 0;

    _clear_buff();
    EVP_MD* md = nullptr;

    do{
        ctx = EVP_PKEY_CTX_new_from_pkey(NULL, this->prv, NULL);
        if(!ctx){
            std::cerr << "Can't generate ctx for decryption\n";
            break;
        }
        if(!EVP_PKEY_decrypt_init_ex(ctx, NULL)){
            std::cerr << "Decrypt init failed\n";
            break;
        }


        md = EVP_MD_fetch(NULL, "SHA256", NULL);
        if(!md){
            std::cerr << "SHA256 fetch fail\n";
            break;
        }

        if (!EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING)){
            std::cerr << "Decryption padding set fail\n";
            break;
        }

        if(!EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md)){
            std::cerr << "OAEP hash set fail\n";
            break;
        }
        if(!EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md)){
            std::cerr << "MGF1 hash set fail\n";
            break;
        }


        if(!EVP_PKEY_decrypt(ctx, NULL, &plen, ciphertext, EVP_PKEY_get_size(prv))){
            std::cerr << "Decryption length check failed\n";
            break;
        }
        out_buff = (unsigned char*)OPENSSL_malloc(plen);

        if(!EVP_PKEY_decrypt(ctx, out_buff, &plen, ciphertext, EVP_PKEY_get_size(prv))){
            std::cerr << "Decryption failed\n";
            break;
        }

        //Trimming

        unsigned char* temp = (unsigned char*)OPENSSL_malloc(plen);
        for(std::size_t i = 0; i < plen; i++){
            temp[i] = out_buff[i];
        }
        OPENSSL_free(out_buff);
        out_buff = temp;
        temp = nullptr;


        out_size = plen;
    }while(0);
    std::printf("out_size = %ld\n", plen);

    ERR_print_errors_fp(stderr);
    EVP_PKEY_CTX_free(ctx);
    EVP_MD_free(md);
}

void RSA_keys::sign(const unsigned char* msg, int msgsize){
    if(!this->prv)
        throw std::logic_error("There is no private key set");
    EVP_MD_CTX* ctx = nullptr;
    std::size_t plen = 0;

    _clear_buff();
    EVP_MD* md = nullptr;


    do{
        ctx = EVP_MD_CTX_new();
        if(!ctx){
            std::cerr << "Can't generate ctx for signature\n";
            break;
        }
        md = EVP_MD_fetch(NULL, "SHA256", NULL);
        if(!md){
            std::cerr << "Can't fetch sha256 for signature\n";
            break;
        }
        //Use RSS-PSS padding !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        
        if(!EVP_DigestSignInit(ctx, NULL, md, NULL, pkey)){//Change to _ex for Openssl 3.0
            std::cerr << "Sig init failed\n";
            break
        }
        if(!EVP_DigestSignFinal(ctx, NULL, &out_size)){
            std::cerr << "Sig get size failed\n";
            break;
        }
        out_buff = (unsigned char*)OPENSSL_malloc(out_size);

    }while(0);

    EVP_MD_free(md);
    EVP_MD_CTX_free(ctx);
}

int RSA_keys::verify(const unsigned char* msg, int msgsize, const unsigned char* signature){
    return 0;
}



