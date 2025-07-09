g++ -o crypto.elf crypt.cpp aes/aes_256_gcm.cpp rsa/rsa.cpp -Wall -Werror -lcrypto -lssl
