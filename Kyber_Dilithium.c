#include "Kyber_Dilithium.h"
#include "./kyber/symmetric.h"

void print(uint8_t *sub, int lengths){
    for(int i = 0; i < lengths; i++)    printf("%02X", sub[i]);
    printf("\n");
}

void sum_buf(uint8_t *A, uint8_t *B, int A_cur_len, int B_len){
    for(int i = 0; i < B_len; i++)  A[A_cur_len + i] = B[i];
}

void print_mess(uint8_t *arr, int len){
    for(int i = 0; i < len; i++){
        if(arr[i] == '\0'){
            printf("\n");
            return;
        }
        printf("%c", arr[i]);
    }
}

int Kyber_KE()
{
    printf("\n--------------------------------- KYBER KE ver. ----------------------------------\n");
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES]; // KYBER_SECRETKEYBYTES = CRYPTO_SECRETKEYBYTES
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    uint8_t key_a[CRYPTO_BYTES];
    uint8_t key_b[CRYPTO_BYTES];

    //Alice generates a public key, private key
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

int Kyber_KE_MITM_Attack(){
    printf("\n\n\n\n------------------------------------ KYBER KE MITM Attack -------------------------------\n");
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    uint8_t key_a[CRYPTO_BYTES];
    uint8_t key_b[CRYPTO_BYTES];

    // Eve Variable
    uint8_t E_pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t E_sk[CRYPTO_SECRETKEYBYTES];
    uint8_t key_A_E[CRYPTO_BYTES];
    uint8_t key_B_E[CRYPTO_BYTES];
    uint8_t arti_ct[CRYPTO_CIPHERTEXTBYTES];

    // Alice generates a public key, private key
    crypto_kem_keypair(pk, sk);

    // Eve receive Alice public key. Create Eve's public key and private key. And send eve's public key to Bob
    crypto_kem_keypair(E_pk, E_sk);

    // Bob receive eve's public key and derives a secret key and creates a response
    crypto_kem_enc(ct, key_b, E_pk);

    // Eve receive ct from Bob. And dec ct using Eve's private key
    // And Generates Artificial Ciphter text using Alice public key. And send Alice.
    crypto_kem_Eve(key_B_E, key_A_E, ct, E_sk, pk, arti_ct);

    // Alice receive artificial cipher text from Eve
    // And derives a secret key.
    crypto_kem_dec(key_a, arti_ct, sk); // key_a is 'K_2

    if(memcmp(key_a, key_A_E, CRYPTO_BYTES)) {
        printf("ERROR keys\n");
        return 1;
    }

    if(memcmp(key_b, key_B_E, CRYPTO_BYTES)) {
        printf("ERROR keys\n");
        return 1;
    }

    printf("Alice Key : ");
    print(key_a, CRYPTO_BYTES);
    printf("Eve with Alice key : ");
    print(key_A_E, CRYPTO_BYTES);
    printf("\nEve with Bob key : ");
    print(key_B_E, CRYPTO_BYTES);
    printf("Bob Key : ");
    print(key_b, CRYPTO_BYTES);
    return 0;
}

int Kyber_AKE(uint8_t *cipher_key){
    printf("\n\n\n\n--------------------------------- KYBER AKE ver. ----------------------------------\n");
    uint8_t pk_A_auth[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk_A_auth[CRYPTO_SECRETKEYBYTES];
    uint8_t pk_B_auth[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk_B_auth[CRYPTO_SECRETKEYBYTES];
    uint8_t pk[CRYPTO_SECRETKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t EK[3*KYBER_SYMBYTES];
    uint8_t EK_p[3*KYBER_SYMBYTES];
    uint8_t EK_T[1*KYBER_SYMBYTES];
    uint8_t ct_1[CRYPTO_CIPHERTEXTBYTES];
    uint8_t ct_2[CRYPTO_CIPHERTEXTBYTES];
    uint8_t key_a[CRYPTO_BYTES];
    uint8_t key_b[CRYPTO_BYTES];

    // Alice and Bob generates a auth public key, auth private key
    crypto_kem_keypair(pk_A_auth, sk_A_auth);
    crypto_kem_keypair(pk_B_auth, sk_B_auth);

    // Alice Generates public key, private key.
    crypto_kem_keypair(pk, sk);

    // Alice encapsulating Bob auth public key
    crypto_kem_enc(ct_2, EK_T, pk_B_auth);
    sum_buf(EK, EK_T, 2*KYBER_SYMBYTES, KYBER_SYMBYTES);
    // and send ct_2, pk

    // Bob receive ct, pk, and decapsulating ct_2 using Bob auth private key
    crypto_kem_dec(EK_T, ct_2, sk_B_auth);
    sum_buf(EK_p, EK_T, 2*KYBER_SYMBYTES, KYBER_SYMBYTES);
    // And encapuslating Alice public key, and Alice auth public key
    crypto_kem_enc(ct_1, EK_T, pk_A_auth);
    sum_buf(EK_p, EK_T, KYBER_SYMBYTES, KYBER_SYMBYTES);
    crypto_kem_enc(ct_2, EK_T, pk);
    sum_buf(EK_p, EK_T, 0, KYBER_SYMBYTES);
    // send ct_1, ct_2

    // Alice receive ct_1, ct_2, and decapsulating ct_2 using Alice private key, ct_1 using Alice auth private key
    crypto_kem_dec(EK_T, ct_2, sk);
    sum_buf(EK, EK_T, 0, KYBER_SYMBYTES);
    crypto_kem_dec(EK_T, ct_1, sk_A_auth);
    sum_buf(EK, EK_T, KYBER_SYMBYTES, KYBER_SYMBYTES);

    // Alice Bob generate share key
    hash_h(key_a, EK, 3*KYBER_SYMBYTES);
    hash_h(key_b, EK_p, 3*KYBER_SYMBYTES);
    hash_h(cipher_key, EK, 3*KYBER_SYMBYTES);

    printf("Alice Key : ");
    print(key_a, CRYPTO_BYTES);
    printf("Bob Key : ");
    print(key_b, CRYPTO_BYTES);

    return 0;
}

void AES_with_Kyber(){
    printf("\n\n\nRun AES algorithm using Kyber Symmetric key\n\n");
    printf("create key using Kyber\n");
    uint8_t cipher_key_256[32];
    Kyber_AKE(cipher_key_256);
    
    char plain[16];
    printf("> input send message(max 16) : ");
    if (fgets(plain, sizeof(plain), stdin) == NULL){
        printf("input error");
        return;
    }

    printf("Encrypt & Decrypt AES algorithm using Kyber symmetric key\n");
    AES_256bit(plain, cipher_key_256);
}

int dilithium5(){
    printf("\n\n\n\n---------------------------- DILITHIUM -----------------------\n");
    size_t j;
    int ret;
    size_t mlen, smlen;
    uint8_t b;
    uint8_t m[MLEN + CRYPTO_BYTES_DILI] = {72,101,108,108,111,32,110,105,99,101,32,116,111,32,109,101,101,116,32,121,111,117,46,32,77,121,32,110,97,109,101,32,105,115,32,73,83,67,77,83,72,89,32,98,101,108,111,110,103,32,116,111,32,75,77,85,110,105,118};
    uint8_t m2[MLEN + CRYPTO_BYTES_DILI];
    uint8_t sm[MLEN + CRYPTO_BYTES_DILI];
    uint8_t pk[CRYPTO_PUBLICKEYBYTES_DILI];
    uint8_t sk[CRYPTO_SECRETKEYBYTES_DILI];

    // randombytes(m, MLEN)
    printf("Message : %s\n", m);

    crypto_sign_keypair(pk, sk);

    crypto_sign(sm, &smlen, m, MLEN, sk);
    printf("Sign Message : ");
    print(sm, MLEN);
    
    ret = crypto_sign_open(m2, &mlen, sm, smlen, pk);
    printf("Verification Message : ");
    print_mess(m2, MLEN);
    
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