#ifndef __RSA_H_
#define __RSA_H_
#endif

#include <openssl/bn.h>
#include "util.h"

BIGNUM* get_rsa_priv_key(BIGNUM* p, BIGNUM* q, BIGNUM* e);
BIGNUM* rsa_encrypt(BIGNUM* message, BIGNUM* mod, BIGNUM* pub_key);
BIGNUM* rsa_decrypt(BIGNUM* encrypted_message, BIGNUM* priv_key, BIGNUM* pub_key);

