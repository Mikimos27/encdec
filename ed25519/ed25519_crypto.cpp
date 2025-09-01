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
        write_prv_to(stdout, NULL);
        write_pub_to(stdout);
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



