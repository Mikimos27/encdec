void RSA_keys::encrypt(const unsigned char* plaintext, int msgsize){
    if(!this->pub)
        throw std::logic_error("There is no public key set");
    EVP_PKEY_CTX* ctx = nullptr;
    //OSSL_LIB_CTX* libctx = nullptr;
    std::size_t clen = 0;

    if(out_buff) delete[] out_buff;
    out_buff = nullptr;
    out_size = 0;
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
        out_buff = new unsigned char[clen];
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

    if(out_buff) delete[] out_buff;
    out_buff = nullptr;
    out_size = 0;
    EVP_MD* md = nullptr;

    do{
        ctx = EVP_PKEY_CTX_new_from_pkey(NULL, this->prv, NULL);
        if(!ctx){
            std::cerr << "Can't generate ctx for encryption\n";
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
        std::cout << "Comp: " << EVP_PKEY_get_size(prv) << ' ' << out_size << "\n";
        //////////////!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        out_buff = new unsigned char[plen];
        if(!EVP_PKEY_decrypt(ctx, out_buff, &plen, ciphertext, EVP_PKEY_get_size(prv))){
            std::cerr << "Decryption failed\n";
            break;
        }
        //////////////!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

        break;
        out_size = plen;
    }while(0);

    ERR_print_errors_fp(stderr);
    EVP_PKEY_CTX_free(ctx);
    EVP_MD_free(md);
}

void RSA_keys::sign(const unsigned char* msg, int msgsize){

}

int RSA_keys::verify(const unsigned char* msg, int msgsize, const unsigned char* signature){
    return 0;
}



