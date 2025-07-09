g++ -o crypto.elf crypt.cpp aes/aes_256_gcm.cpp rsa/rsa_pss.cpp -Wall -Werror -lcrypto -lssl
