#include <stdio.h>
#include "Kyber_Dilithium.h"

int main(void)
{
    uint8_t cipher_key_256[32];
    Kyber_KE();
    Kyber_KE_MITM_Attack();
    Kyber_AKE(cipher_key_256);
    dilithium5();
    AES_with_Kyber();
    return 0;
}