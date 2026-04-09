#ifndef CREATEHASH_H
#define CREATEHASH_H
#include <openssl/evp.h>

int sha256(unsigned char *buffer, int bytesRead, unsigned char *hash, unsigned int *hashLength);

#endif
