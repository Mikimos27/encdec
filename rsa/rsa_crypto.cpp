void RSA_keys::encrypt(const unsigned char* plaintext, unsigned char* ciphertext, int size);
void RSA_key::sdecrypt(const unsigned char* ciphertext, unsigned char* plaintext, int size);
void RSA_keys::sign(const unsigned char* msg, int msgsize, unsigned char* signature);
int RSA_keys::verify(const unsigned char* msg, int msgsize, const unsigned char* signature);


