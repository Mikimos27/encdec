#include "../hdr/aes.h"
#include "../hdr/dh.h"
#include "../hdr/ed25519.h"
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


    aes.genIV();
    if(aes.encrypt(in, cipher, len)) std::cerr << "Enc failed\n";

    print_hex("ciphertext", cipher, len);
    print_hex("tag", aes.get_tag(), AES_GCM::TAGLEN);
    print_hex("iv", aes.get_iv(), AES_GCM::IVLEN);
    print_hex("key", aes.get_key(), AES_GCM::KEYLEN);


    if(aes.decrypt(cipher, out, len)) std::cerr << "Dec failed\n";
    
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


int test_sig(int argc, char** argv){
    Ed25519 edcs;
    edcs.gen_key_pair(256);

    if(edcs.write_pubPEM("pub.pem")) std::cerr << "write to pub.pem F\n";
    if(edcs.write_prvPEM("prv.pem", NULL)) std::cerr << "write to prv.pem F\n";
    if(edcs.load_pubPEM("pub.pem")) std::cerr << "load from pub.pem F\n";
    if(edcs.load_prvPEM("prv.pem", NULL)) std::cerr << "load from prv.pem F\n";

    char p1[2] = "a";
    char p2[2] = "a";

    if(edcs.write_pubPEM("pub.pem")) std::cerr << "write to pub.pem F\n";
    if(edcs.write_prvPEM("prv.pem", p1)) std::cerr << "write to prv.pem F\n";
    if(edcs.load_pubPEM("pub.pem")) std::cerr << "load from pub.pem F\n";
    if(edcs.load_prvPEM("prv.pem", p2)) std::cerr << "load from prv.pem F\n";


    const char* msg = "Halo halo halo kurna";
    if(argc < 2){
        std::cerr << "No message given or message too long\nUsing defaults\n";
    }
    else msg = argv[1];
    if(edcs.sign((const unsigned char*)msg, std::strlen(msg))) std::cerr << "Sig failed\n";

    unsigned char* get = new unsigned char[edcs.get_out_size() + 1];
    size_t size = edcs.get_out_size();
    printf("outsize = %ld\n", edcs.get_out_size());
    std::memcpy(get, edcs.get_out_buff(), size);
    get[size] = 0;

    std::cout << "Msg: " << msg << '\n';
    print_hex("Sig", get, size);

    if(edcs.verify((const unsigned char*)msg, std::strlen(msg), get, size)){
        std::cerr << "Bad signature\n";
    }else std::cout << "Good signature :)\n";

    delete[] get;
    ERR_print_errors_fp(stderr);
    return 0;
}

int test_dh(int argc, char** argv){
    DH_protocol dh1, dh2;

    std::cout << "\n\n";
    if(dh1.gen_key()) std::cerr << "DH genkey F\n";
    if(dh2.gen_key()) std::cerr << "DH genkey F\n";
    EVP_PKEY* pub1 = nullptr, *pub2 = nullptr;
    
    if(dh1.extract_pub(&pub1)) std::cerr << "DH extract F\n";
    if(dh2.extract_pub(&pub2)) std::cerr << "DH extract F\n";

    constexpr size_t saltlen = AES_GCM::KEYLEN;
    unsigned char salt[saltlen] = {0};
    RAND_bytes(salt, saltlen);

    unsigned char iv[AES_GCM::IVLEN] = {0};
    RAND_bytes(iv, AES_GCM::IVLEN);
    print_hex("IV", iv, AES_GCM::IVLEN);

    if(dh1.gen_secret(pub2)) std::cerr << "DH secret F\n";
    if(dh2.gen_secret(pub1)) std::cerr << "DH secret F\n";

    char aad[] = "additional auth data";

    auto k1 = *dh1.gen_aes(salt, saltlen, aad);
    auto k2 = *dh2.gen_aes(salt, saltlen, aad);

    if(k1.set_iv(iv)) std::cerr << "DH set iv F\n";
    if(k2.set_iv(iv)) std::cerr << "DH set iv F\n";

    //share aad

    print_hex("k1", k1.get_key(), AES_GCM::KEYLEN);
    print_hex("k2", k2.get_key(), AES_GCM::KEYLEN);

    EVP_PKEY_free(pub1);
    EVP_PKEY_free(pub2);


    return 0;
}

int main(int argc, char** argv){
    test_aes(argc, argv);
    test_sig(argc, argv);
    return test_dh(argc, argv);
}
