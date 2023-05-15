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

//  Kyber
int Kyber_KE();
int Kyber_KE_MITM_Attack();
// int Kyber_AKE();

// Dilithium
int dilithium5();
