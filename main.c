#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "./kyber/kem.h"
#include "./kyber/randombytes.h"
#include "./dilithium/randombytes.h"
#include "./dilithium/sign.h"

#define MLEN 59

// Key Exchange Protocol is Kyber

int Kyber_KE();
int dilithium5();
void print();

int main(void)
{
    Kyber_KE();
    dilithium5();

    return 0;
}

void print(uint8_t *sub, int lengths){
    for(int i = 0; i < lengths; i++)    printf("%02X", sub[i]);
    printf("\n");
}

int Kyber_KE()
{
    printf("\n---------------------------- KYBER -----------------------\n");
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES]; // KYBER_SECRETKEYBYTES = CRYPTO_SECRETKEYBYTES
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    uint8_t key_a[CRYPTO_BYTES];
    uint8_t key_b[CRYPTO_BYTES];

    //Alice generates a public key
    crypto_kem_keypair(pk, sk);

    //Bob derives a secret key and creates a response
    crypto_kem_enc(ct, key_b, pk); // key_b is K_2

    //Alice uses Bobs response to get her shared key
    crypto_kem_dec(key_a, ct, sk); // key_a is 'K_2

    if(memcmp(key_a, key_b, CRYPTO_BYTES)) {
        printf("ERROR keys\n");
        return 1;
    }
    printf("Alice Key : ");
    print(key_a, CRYPTO_BYTES);
    printf("Bob Key : ");
    print(key_b, CRYPTO_BYTES);
    return 0;
}

int dilithium5(){
    printf("\n---------------------------- DILITHIUM -----------------------\n");
    size_t j;
    int ret;
    size_t mlen, smlen;
    uint8_t b;
    uint8_t m[MLEN + CRYPTO_BYTES_DILI] = {72,101,108,108,111,32,110,105,99,101,32,116,111,32,109,101,101,116,32,121,111,117,46,32,77,121,32,110,97,109,101,32,105,115,32,73,83,67,77,83,72,89,32,98,101,108,111,110,103,32,116,111,32,80,69,80,83,73,46};
    uint8_t m2[MLEN + CRYPTO_BYTES_DILI];
    uint8_t sm[MLEN + CRYPTO_BYTES_DILI];
    uint8_t pk[CRYPTO_PUBLICKEYBYTES_DILI];
    uint8_t sk[CRYPTO_SECRETKEYBYTES_DILI];

    // randombytes(m, MLEN)
    printf("Message : ");
    printf("%s\n", m);

    crypto_sign_keypair(pk, sk);

    crypto_sign(sm, &smlen, m, MLEN, sk);
    printf("Sign Message : ");
    print(sm, MLEN);
    
    ret = crypto_sign_open(m2, &mlen, sm, smlen, pk);
    printf("Verification Message : ");
    printf("%s\n", m2);
    
    if(ret) {
        fprintf(stderr, "Verification failed\n");
        return -1;
    }
    if(smlen != MLEN + CRYPTO_BYTES_DILI) {
        fprintf(stderr, "Signed message lengths wrong\n");
        return -1;
    }
    if(mlen != MLEN) {
        fprintf(stderr, "Message lengths wrong\n");
        return -1;
    }
    for(j = 0; j < MLEN; ++j) {
        if(m2[j] != m[j]) {
            fprintf(stderr, "Messages don't match\n");
            return -1;
        }
    }

    randombytes((uint8_t *)&j, sizeof(j));
    do {
        randombytes(&b, 1);
    } while(!b);

    sm[j % (MLEN + CRYPTO_BYTES_DILI)] += b;

    ret = crypto_sign_open(m2, &mlen, sm, smlen, pk);

    if(!ret) {
        fprintf(stderr, "Trivial forgeries possible\n");
        return -1;
    }
    return 0;
}