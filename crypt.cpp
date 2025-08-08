#include "aes/aes.h"
#include "rsa/rsa.h"
#include "dh/dh.h"
extern "C"{
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
}
#include <iostream>
#include <cstdio>
#include <cstddef>
#include <cstring>
#include <string>
#define OPENSSL_API_COMPAT 0x30500010

using std::size_t;
using uchar = unsigned char;

void print_hex(const char* name, const uchar* str, size_t len){
    std::printf("%s = ", name);
    for(size_t i = 0; i < len; i++){
        std::printf("%02x", str[i]);
    }
    std::printf("\n");
}

int test_aes(int argc, char** argv){
    if(argc < 2){
        std::cerr << "Usage: " << argv[0] << " <plaintext>\n";
        return 1;
    }

    std::string input(argv[1]);
    int len = (int)input.length();
    uchar* in = new uchar[len]{0};
    uchar* cipher = new uchar[len]{0};
    uchar* out = new uchar[len]{0};


    AES_GCM aes_1("ExampleAAD");
    AES_GCM aes = aes_1;

    for(int i = 0; i < len; i++){
        in[i] = (uchar)input.at(i);
    }
    aes.encrypt(in, cipher, len);

    print_hex("ciphertext", cipher, len);
    print_hex("tag", aes.get_tag(), AES_GCM::TAGLEN);
    print_hex("iv", aes.get_iv(), AES_GCM::IVLEN);
    print_hex("key", aes.get_key(), AES_GCM::KEYLEN);


    aes.decrypt(cipher, out, len);
    
    std::cout << "Decrypted: ";
    for(int i = 0; i < len; i++){
        std::printf("%c", (char)out[i]);
    }
    printf("\nlen = %d\n", len);
    std::printf("\n");


    delete[] in;
    delete[] cipher;
    delete[] out;
    return 0;
}


int test_rsa(int argc, char** argv){
    int keysize = 1024;
    if(argc < 2){
        std::cout << "No key size given\nUsing default: 4096\n";
    }
    else {
        try{
            keysize = std::stoi(argv[1]);
        }catch(...){
            std::cerr << "NAN given\n";
            return 1;
        }
    }
    RSA_keys rsa;
    if(rsa.gen_key_pair(keysize) < 0){
        std::cerr << "Keys can't be generated\n";
        return 1;
    }
    if(rsa.gen_key_pair(keysize) < 0){
        std::cerr << "Keys can't be generated\n";
        return 1;
    }
    rsa.write_pubPEM("pub.pem");
    rsa.write_prvPEM("prv.pem", NULL);
    rsa.load_pubPEM("pub.pem");
    try {
       rsa.load_prvPEM("prv.pem", NULL);
    } catch(std::exception& E){
        std::cerr << "Error caught!\n";
        std::cerr << E.what() << '\n';
        return 1;
    }
    char p1[2] = "a";
    char p2[2] = "a";
    rsa.write_pubPEM("pub.pem");
    rsa.write_prvPEM("prv.pem", p1);
    rsa.load_pubPEM("pub.pem");
    try {
       rsa.load_prvPEM("prv.pem", p2);
    } catch(std::exception& E){
        std::cerr << "Error caught!\n";
        std::cerr << E.what() << '\n';
        return 1;
    }

    const char* msg = "Halo halo halo kurna";
    if(argc < 2){
        std::cerr << "No message given or message too long\nUsing defaults\n";
    }
    else msg = argv[1];
    try{
        rsa.encrypt((const unsigned char*)msg, std::strlen(msg));
    }catch(const std::exception& E){
        std::cout << E.what() << '\n';
        return 1;
    }
    int size = rsa.get_out_size();
    unsigned char* enc = new unsigned char[size];
    std::memcpy(enc, rsa.get_out_buff(), size);//UNINIT VALUE
    print_hex("encrypted string", rsa.get_out_buff(), size);
    print_hex("encrypted string", enc, size);
    std::printf("HERE\n");


    rsa.decrypt(enc);

    unsigned char* get = new unsigned char[rsa.get_out_size() + 1];
    printf("outsize = %ld\n", rsa.get_out_size());
    std::memcpy(get, rsa.get_out_buff(), rsa.get_out_size());
    get[rsa.get_out_size()] = 0;
    



    std::printf("Decrypted string = ");
    std::fwrite(get, 1, rsa.get_out_size(), stdout);
    std::cout << get << "\nout_size = " << rsa.get_out_size() << '\n';

    delete[] get;
    delete[] enc;

    ERR_print_errors_fp(stderr);
    return 0;
}

int test_sig(int argc, char** argv){
    RSA_keys rsa;
    rsa.gen_key_pair(1024);


    const char* msg = "Halo halo halo kurna";
    if(argc < 2){
        std::cerr << "No message given or message too long\nUsing defaults\n";
    }
    else msg = argv[1];
    try{
        rsa.sign((const unsigned char*)msg, std::strlen(msg));
    }catch(const std::exception& E){
        std::cout << E.what() << '\n';
        return 1;
    }

    unsigned char* get = new unsigned char[rsa.get_out_size() + 1];
    size_t size = rsa.get_out_size();
    printf("outsize = %ld\n", rsa.get_out_size());
    std::memcpy(get, rsa.get_out_buff(), size);
    get[size] = 0;

    std::cout << "Msg: " << msg << '\n';
    print_hex("Sig", get, size);

    if(rsa.verify((const unsigned char*)msg, std::strlen(msg), get, size)){
        std::cerr << "Bad signature\n";
    }else std::cout << "Good signature :)\n";

    delete[] get;
    ERR_print_errors_fp(stderr);
    return 0;
}

int test_dh(int argc, char** argv){
    DH_protocol dh1, dh2;

    dh1.gen_key();
    dh2.gen_key();
    EVP_PKEY* pub1 = nullptr, *pub2 = nullptr;
    
    dh1.extract_pub(&pub1);
    dh2.extract_pub(&pub2);

    constexpr size_t saltlen = AES_GCM::KEYLEN;
    unsigned char salt[saltlen] = {0};
    RAND_bytes(salt, saltlen);

    unsigned char iv[AES_GCM::IVLEN] = {0};
    RAND_bytes(iv, AES_GCM::IVLEN);

    dh1.gen_secret(pub2);
    dh2.gen_secret(pub1);

    auto k1 = dh1.gen_aes(salt, saltlen);
    auto k2 = dh2.gen_aes(salt, saltlen);

    k1.set_iv(iv);
    k2.set_iv(iv);

    print_hex("k1", k1.get_key(), AES_GCM::KEYLEN);
    print_hex("k2", k2.get_key(), AES_GCM::KEYLEN);

    EVP_PKEY_free(pub1);
    EVP_PKEY_free(pub2);


    return 0;
}

int main(int argc, char** argv){
    return test_dh(argc, argv);
}
