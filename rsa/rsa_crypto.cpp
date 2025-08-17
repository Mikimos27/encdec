void RSA_keys::encrypt(const unsigned char* plaintext, int msglen){
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


        if(!EVP_PKEY_encrypt(ctx, NULL, &clen, plaintext, msglen)){
            std::cerr << "Encryption length check failed\n";
            break;
        }
        out_buff = (unsigned char*)OPENSSL_malloc(clen);
        if(!EVP_PKEY_encrypt(ctx, out_buff, &clen, plaintext, msglen)){
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

void RSA_keys::sign(const unsigned char* msg, int msglen){
    if(!this->prv)
        throw std::logic_error("There is no private key set");
    EVP_MD_CTX* ctx = nullptr;
    EVP_PKEY_CTX* pctx = nullptr;
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
        if(!EVP_DigestSignInit(ctx, &pctx, md, NULL, this->prv)){//Change to _ex for Openssl 3.0
            std::cerr << "Sig init failed\n";
            break;
        }
        if(!EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING)){
            std::cerr << "Sig set padding failed\n";
            break;
        }
        if(!EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, md)){
            std::cerr << "Sig mgf1 failed\n";
            break;
        }
        if(!EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST)){ //RSA_PSS_SALTLEN_DIGEST = -1
            std::cerr << "Sig pss saltlen length failed\n";
            break;
        }
        if(!EVP_DigestSignUpdate(ctx, (void*)msg, msglen)){
            std::cerr << "Sig msg update failed\n";
            break;
        }
        if(!EVP_DigestSignFinal(ctx, NULL, &plen)){
            std::cerr << "Sig get size failed\n";
            break;
        }
        out_buff = (unsigned char*)OPENSSL_malloc(plen);
        if(!EVP_DigestSignFinal(ctx, out_buff, &plen)){
            std::cerr << "Sig gen failed\n";
            break;
        }

        out_size = plen;

    }while(0);

    EVP_MD_free(md);
    EVP_MD_CTX_free(ctx);
}

int RSA_keys::verify(const unsigned char* msg, int msglen, const unsigned char* signature, int siglen){
    EVP_PKEY_CTX* pctx = nullptr;
    EVP_MD_CTX* mctx = nullptr;
    EVP_MD* md = nullptr;
    int failed = 1;
    do{
        mctx = EVP_MD_CTX_new();
        if(!mctx){
            std::cerr << "Verify EVP_MD_CTX_new() failed\n";
            break;
        }
        md = EVP_MD_fetch(NULL, "SHA256", NULL);
        if(!md){
            std::cerr << "Verify md fetch failed\n";
            break;
        }
        if(!EVP_DigestVerifyInit(mctx, &pctx, md, NULL, this->pub)){
            std::cerr << "Verify init failed\n";
            break;
        }

        if(!EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING)){
            std::cerr << "Verify set padding failed\n";
            break;
        }
        if(!EVP_PKEY_CTX_set_signature_md(pctx, md)){
            std::cerr << "Verify set md failed\n";
            break;
        }
        if(!EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST)){
            std::cerr << "Verify set saltlen failed\n";
            break;
        }

        if(!EVP_DigestVerifyUpdate(mctx, msg, msglen)){
            std::cerr << "Verify update failed\n";
            break;
        }
        if(!EVP_DigestVerifyFinal(mctx, signature, siglen)){
            std::cerr << "Verification failed\n";
            break;
        }
        failed = 0;
    }while(0);

    EVP_MD_free(md);
    EVP_MD_CTX_free(mctx);
    return failed;
}



