#ifndef RSA_H
#define RSA_H
extern "C"{
#include <openssl/evp.h>
#include <openssl/rsa.h>
}
#include <string>
#include <cstdio>
#include <cstddef>


class RSA_keys{
public:
    RSA_keys();
    ~RSA_keys();

    void load_pubPEM(const char* filepath);
    void write_pubPEM(const char* filepath);
    void load_pubDER(const char* filepath);
    void write_pubDER(const char* filepath);
    void write_pub_to(std::FILE* const fp);

    void load_prvPEM(const char* filepath, const char* passwd);
    void write_prvPEM(const char* filepath, const char* passwd);
    void load_prvDER(const char* filepath, const char* passwd);
    void write_prvDER(const char* filepath, const char* passwd);
    void write_prv_to(std::FILE* const fp, const char* const passwd);

    void set_key_prv(EVP_PKEY** keys); //Takes ownership
    const EVP_PKEY* const get_key_prv();

    void set_key_pub(EVP_PKEY** keys); //Takes ownership
    const EVP_PKEY* const get_key_pub();

    int gen_key_pair(int keysize);
    

    void encrypt(const unsigned char* plaintext, int msgsize);
    void decrypt(const unsigned char* ciphertext);//Check if ciphertext length is equal to the size of the key!!!!!!
    void sign(const unsigned char* msg, int msgsize);
    int verify(const unsigned char* msg, int msgsize, const unsigned char* signature);

    const unsigned char* const get_out_buff();
    const std::size_t get_out_size();

private:
    
    EVP_PKEY* _extract_pub(EVP_PKEY* pkey);


    EVP_PKEY* prv;
    EVP_PKEY* pub;
    int keysize;

    unsigned char* out_buff;
    std::size_t out_size;
};

#endif
