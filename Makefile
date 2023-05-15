CC = /usr/bin/gcc 
CFLAGS += -Wall -Wextra -Wpedantic -Wredundant-decls -Wshadow -Wvla -Wpointer-arith -O3 -fomit-frame-pointer -Wno-vla

# kyber
KYBER_DIR = ./kyber
# -- SOURCE
KYBER_SOURCES = $(KYBER_DIR)/kex.c $(KYBER_DIR)/kem.c $(KYBER_DIR)/indcpa.c $(KYBER_DIR)/polyvec.c $(KYBER_DIR)/poly.c $(KYBER_DIR)/ntt.c \
	$(KYBER_DIR)/cbd.c $(KYBER_DIR)/reduce.c $(KYBER_DIR)/verify.c
KYBER_SOURCESKECCAK = $(KYBER_SOURCES) $(KYBER_DIR)/fips202.c $(KYBER_DIR)/symmetric-shake.c
# -- HEADERS
KYBER_HEADERS = $(KYBER_DIR)/params.h $(KYBER_DIR)/kex.h $(KYBER_DIR)/kem.h $(KYBER_DIR)/indcpa.h $(KYBER_DIR)/polyvec.h $(KYBER_DIR)/poly.h \
	$(KYBER_DIR)/ntt.h $(KYBER_DIR)/cbd.h $(KYBER_DIR)/reduce.c $(KYBER_DIR)/verify.h $(KYBER_DIR)/symmetric.h
KYBER_HEADERSKECCAK = $(KYBER_HEADERS) $(KYBER_DIR)/fips202.h


# dilithiium
DILI_DIR = ./dilithium
# -- SOURCE
DILI_SOURCES = $(DILI_DIR)/sign.c $(DILI_DIR)/packing.c $(DILI_DIR)/polyvec.c $(DILI_DIR)/poly.c $(DILI_DIR)/ntt.c \
	$(DILI_DIR)/reduce.c $(DILI_DIR)/rounding.c
DILI_SOURCESKECCAK = $(DILI_SOURCES) $(DILI_DIR)/fips202.c $(DILI_DIR)/symmetric-shake.c
# -- HEADERS
DILI_HEADERS = $(DILI_DIR)/config.h $(DILI_DIR)/config.h $(DILI_DIR)/params.h $(DILI_DIR)/api.h $(DILI_DIR)/sign.h $(DILI_DIR)/packing.h \
	$(DILI_DIR)/polyvec.h $(DILI_DIR)/poly.h $(DILI_DIR)/ntt.h $(DILI_DIR)/reduce.h $(DILI_DIR)/rounding.h $(DILI_DIR)/symmetric.h $(DILI_DIR)/randombytes.h
DILI_HEADERSKECCAK = $(DILI_HEADERS) $(DILI_DIR)/fips202.h


make: $(KYBER_SOURCESKECCAK) $(KYBER_HEADERSKECCAK) $(DILI_SOURCESKECCAK) $(DILI_HEADERSKECCAK) main.c $(KYBER_DIR)/randombytes.c ./AES/AES_func.c ./Kyber_Dilithium.h ./Kyber_Dilithium.c
	$(CC) $(CFLAGS) -DKYBER_K=2 -DDILITHIUM_MODE=5 $(KYBER_SOURCESKECCAK) $(DILI_SOURCESKECCAK) $(KYBER_DIR)/randombytes.c ./AES/AES_func.c ./Kyber_Dilithium.c main.c -o main
