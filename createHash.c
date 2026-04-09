#include "createHash.h"

/******************************************************************/
/* this function hashes a chunk, returns 1 on success and 0 on    */
/* failure                                                        */
/******************************************************************/
int sha256(unsigned char *buffer, int bytesRead, unsigned char *hash, unsigned int *hashLength){
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

    if (!mdctx){
        return 0;
    }

    // Initialize the context for SHA-256 for chunk                                                                        
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(mdctx);
        return 0;
    }

    if (EVP_DigestUpdate(mdctx, buffer, bytesRead) != 1 ){
        EVP_MD_CTX_free(mdctx);
        return 0;
    }

    if (EVP_DigestFinal_ex(mdctx, hash, hashLength) != 1) {
        EVP_MD_CTX_free(mdctx);
        return 0;
    }
    // Clean up the chunk context                                                                                          
    EVP_MD_CTX_free(mdctx);
    return 1;
}
