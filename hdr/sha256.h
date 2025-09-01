extern "C"{
#include <openssl/evp.h>
}
#include <array>
#include <expected>
#include "error.h"


std::expected<std::array<unsigned char, 32>, ErrorType> calc_sha256(unsigned char* msg, int msglen);
