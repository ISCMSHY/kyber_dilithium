#include <stdio.h>
#include <stdint.h>

extern const int standard_row;
extern const int standard_column;

/* ------------------------------- Debugging or Testing Functions -------------------------------*/
void print_block(int row, int column, uint8_t (*input)[column]);
void print_stream(int row, int column, uint8_t (*input)[column]);
void print_text(int row, int column, uint8_t (*input)[column]);
void SubBytes_test(uint8_t (*input)[standard_column]);
void Shift_Row_test(uint8_t (*input)[standard_column]);
void Mix_columns_test(uint8_t (*input)[standard_column]);

void set_text(uint8_t Text[standard_row][standard_column], char *plaintext);
void set_key(int col, uint8_t cipher_key[standard_row][col], uint8_t *key);

/* ------------------------------- SubBytes -------------------------------*/
void SubBytes(uint8_t (*input)[standard_column], int type);

/* ------------------------------- Shift Row ------------------------------- */
void Shift_Left_Rotation(uint8_t input[standard_column], int count);
void Shift_Right_Rotation(uint8_t input[standard_column], int count);
void Shift_Row(uint8_t (*input)[standard_column]);
void Inv_Shift_Row(uint8_t (*input)[standard_column]);

/* ------------------------------- MixColumn ------------------------------- */
uint8_t calc_mod(uint8_t input);
uint8_t multiply(uint8_t a, uint8_t b);
void Calc_Matrix(uint8_t (*input)[standard_column], int column, int type);
void Mix_columns(uint8_t (*input)[standard_column], int type);

/* ------------------------------- AddRoundKey ------------------------------- */
void Add_Round_Key(uint8_t (*input)[standard_column], uint8_t (*round_key)[standard_column]);

/* ------------------------------- Key Schduling ------------------------------- */
void create_round_key(int round, int key_block, uint8_t (*input)[key_block], uint8_t output[standard_row][key_block]);
void Key_Scheduling(int round, int key_block, uint8_t (*cipher_key)[key_block], uint8_t (*round_key)[standard_row][key_block]);

/* ------------------------------- encrypt and decrypt ------------------------------- */
void encrypt(uint8_t (*plaintext)[], uint8_t (*round_key)[standard_row][standard_column], int round);
void decrypt(uint8_t (*ciphertext)[], uint8_t (*round_key)[standard_row][standard_column], int round);

/* ------------------------------- AES 192bit round_key seperate --------------------- */
void seperate_round_key(int column, uint8_t (*output)[standard_row][standard_column], uint8_t (*input)[standard_row][column], int bit);

void AES_128bit(char *plaintext, uint8_t key[standard_row * 4]);
void AES_192bit(char *plaintext, uint8_t key[standard_row * 6]);
void AES_256bit(char *plaintext, uint8_t key[standard_row * 8]);