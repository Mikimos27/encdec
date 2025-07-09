#ifndef RSA_H
#define RSA_H
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <string>


class RSA_keys{
public:
    RSA_keys();
    ~RSA_keys();

    void load_pubPEM(const char* filepath);
    void write_pubPEM(const char* filepath);
    void load_pubDER(const char* filepath);
    void write_pubDER(const char* filepath);

    void load_prvPEM(const char* filepath, const char* passwd);
    void write_prvPEM(const char* filepath, const char* passwd);
    void load_prvDER(const char* filepath, const char* passwd);
    void write_prvDER(const char* filepath, const char* passwd);

    void set_key(EVP_PKEY** keys);
    void get_key(EVP_PKEY** keys);

    void gen_key_pair(int keysize);
    

    void encrypt(const unsigned char* plaintext, unsigned char* ciphertext, int size);
    void decrypt(const unsigned char* ciphertext, unsigned char* plaintext, int size);
    void sign(const unsigned char* msg, unsigned char* signature, int size);
    int verify(const unsigned char* msg, const unsigned char* signature, int size);

private:
    
    EVP_PKEY* _extract_pub(EVP_PKEY* pkey);


    EVP_PKEY* prv;
    EVP_PKEY* pub;
    int keysize;
};

#endif
