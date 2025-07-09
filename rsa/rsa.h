#include <openssl/evp.h>
#include <openssl/rsa.h>


class RSA_keys{
public:
    RSA_keys();
    ~RSA_keys();

    void load_pubPEM(const char* filepath, const std::string& passwd);
    void load_prvPEM(const char* filepath, const std::string& passwd);
    void load_pubDER(const char* filepath, const std::string& passwd);
    void load_prvDER(const char* filepath, const std::string& passwd);

    void write_pubPEM(const char* filepath, const std::string& passwd);
    void write_prvPEM(const char* filepath, const std::string& passwd);
    void write_pubDER(const char* filepath, const std::string& passwd);
    void write_prvDER(const char* filepath, const std::string& passwd);

    void set_key(EVP_PKEY** keys);
    void get_key(EVP_PKEY** keys);

    void gen_key_pair(int keysize);

private:
    EVP_PKEY* prv;
    EVP_PKEY* pub;
};
