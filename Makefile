CC ?= /usr/bin/cc
CFLAGS += -Wall -Wextra -Wpedantic -Wredundant-decls -Wshadow -Wvla -Wpointer-arith -O3 -fomit-frame-pointer

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

# SOURCES = $(DIR)/kex.c $(DIR)/kem.c $(DIR)/indcpa.c $(DIR)/polyvec.c $(DIR)/poly.c $(DIR)/ntt.c $(DIR)/cbd.c $(DIR)/reduce.c $(DIR)/verify.c \
# 	$(DIR)/sign.c $(DIR)/packing.c $(DIR)/polyvec_dili.c $(DIR)/poly_dili.c $(DIR)/ntt_dili.c $(DIR)/reduce_dili.c $(DIR)/rounding.c
# SOURCESKECCAK = $(SOURCES) $(DIR)/fips202.c $(DIR)/symmetric-shake.c $(DIR)/fips202_dili.c $(DIR)/symmetric-shake_dili.c

# HEADERS = $(DIR)/params.h $(DIR)/kex.h $(DIR)/kem.h $(DIR)/indcpa.h $(DIR)/polyvec.h $(DIR)/poly.h $(DIR)/ntt.h $(DIR)/cbd.h $(DIR)/reduce.c $(DIR)/verify.h $(DIR)/symmetric.h \
# 	$(DIR)/config.h $(DIR)/config.h $(DIR)/params_dili.h $(DIR)/api.h $(DIR)/sign.h $(DIR)/packing.h $(DIR)/polyvec_dili.h $(DIR)/poly_dili.h $(DIR)/ntt_dili.h $(DIR)/reduce_dili.h $(DIR)/rounding.h \
# 	$(DIR)/symmetric_dili.h $(DIR)/randombytes_dili.h
# HEADERSKECCAK = $(HEADERS) $(DIR)/fips202.h $(DIR)/fips202_dili.h


make: $(KYBER_SOURCESKECCAK) $(KYBER_HEADERSKECCAK) $(DILI_SOURCESKECCAK) $(DILI_HEADERSKECCAK) main.c $(KYBER_DIR)/randombytes.c
	$(CC) $(CFLAGS) -DKYBER_K=2 -DDILITHIUM_MODE=5 $(KYBER_SOURCESKECCAK) $(DILI_SOURCESKECCAK) $(KYBER_DIR)/randombytes.c main.c -o main
