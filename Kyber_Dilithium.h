#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "./kyber/kem.h"
#include "./kyber/randombytes.h"
#include "./dilithium/randombytes.h"
#include "./dilithium/sign.h"
#include "./AES/AES_func.h"

#define MLEN 59

void print(uint8_t *sub, int lengths);
void sum_buf(uint8_t *A, uint8_t *B, int A_cur_len, int B_len);
void print_mess(uint8_t *arr, int len);

//  Kyber
int Kyber_KE();
int Kyber_KE_MITM_Attack();
int Kyber_AKE(uint8_t *cipher_key);
void AES_with_Kyber();

// Dilithium
int dilithium5();
