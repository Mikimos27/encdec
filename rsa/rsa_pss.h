#ifndef RSA_PSS_H
#define RSA_PSS_H
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <string>


class RSA_PSS_keys{
public:
    RSA_PSS_keys();
    ~RSA_PSS_keys();

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

private:
    
    EVP_PKEY* _extract_pub(EVP_PKEY* pkey);


    EVP_PKEY* prv;
    EVP_PKEY* pub;
};

#endif
