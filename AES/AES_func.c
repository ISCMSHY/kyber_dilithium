#include "AES_func.h"
#include "AES_table.h"

const int standard_row = 4;
const int standard_column = 4;

/* ------------------------------- Debugging or Testing Functions -------------------------------*/
void print_block(int row, int column, uint8_t (*input)[column]){
    for(int i = 0; i < row; i++){
        for(int j = 0; j < column; j++) printf("0x%x, ", input[i][j]);
        printf("\n");
    }
}
void print_stream(int row, int column, uint8_t (*input)[column]){
    for(int i = 0; i < row; i++){
        for(int j = 0; j < column; j++) printf("%02x", input[j][i]);
    }
    printf("\n");
}

void print_text(int row, int column, uint8_t (*input)[column]){
    for(int i = 0; i < row; i++){
        for(int j = 0; j < column; j++){
            if(input[j][i] == '\0'){
                printf("\n");
                return;
            }
            printf("%c", input[j][i]);
        }
    }
    printf("\n");
}

void set_text(uint8_t Text[standard_row][standard_column], char *plaintext){
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++)
            Text[j][i] = (int)plaintext[4*i + j];
    }
}

void set_key(int col, uint8_t cipher_key[standard_row][col], uint8_t *key){
    for(int i = 0; i < col; i++){
        for(int j = 0; j < 4; j++)
            cipher_key[j][i] = key[4*i + j];
    }
}

void SubBytes_test(uint8_t (*input)[standard_column]){
    printf("--------- Origin block State ---------\n");
    print_block(standard_row, standard_column, input);
    SubBytes(input, 0);
    printf("--------- Run SBox State ---------\n");
    print_block(standard_row, standard_column, input);
    SubBytes(input, 1);
    printf("--------- Run Inv SBox State ---------\n");
    print_block(standard_row, standard_column, input);
}

void Shift_Row_test(uint8_t (*input)[standard_column]){
    printf("--------- Origin block State ---------\n");
    print_block(standard_row, standard_column, input);
    Shift_Row(input);
    printf("--------- Run Shift Row State ---------\n");
    print_block(standard_row, standard_column, input);
    Inv_Shift_Row(input);
    printf("--------- Run Inv Shift Row State ---------\n");
    print_block(standard_row, standard_column, input);
}

void Mix_columns_test(uint8_t (*input)[standard_column]){
    printf("--------- Origin block State ---------\n");
    print_block(standard_row, standard_column, input);
    Mix_columns(input, 0);
    printf("--------- Run Mix columns State ---------\n");
    print_block(standard_row, standard_column, input);
    Mix_columns(input, 1);
    printf("--------- Run Inv Mix columns State ---------\n");
    print_block(standard_row, standard_column, input);
}

/* ------------------------------- SubBytes -------------------------------*/
// type == 0 then encrypt, type == 1 then decrypt
void SubBytes(uint8_t (*input)[standard_column], int type){
    for(int i = 0; i < standard_row; i++)   for(int j = 0; j < standard_column; j++)  input[i][j] = S_BOX_Array[type][input[i][j]];
}

/* ------------------------------- Shift Row ------------------------------- */

void Shift_Left_Rotation(uint8_t input[standard_column], int count){
    uint8_t temp = 0;
    for(int i = 0; i < count; i++){
        temp = input[0];
        for(int j = 0; j < standard_column - 1; j++)
            input[j] = input[j+1];
        input[standard_column - 1] = temp;
    }
}

void Shift_Right_Rotation(uint8_t input[standard_column], int count){
    uint8_t temp = 0;
    for(int i = 0; i < count; i++){
        temp = input[3];
        for(int j = standard_column - 1; j > 0 ; j--)
            input[j] = input[j-1];
        input[0] = temp;
    }
}

void Shift_Row(uint8_t (*input)[standard_column]){
    for(int i = 1; i < standard_row; i++)  Shift_Left_Rotation(input[i], i);
}

void Inv_Shift_Row(uint8_t (*input)[standard_column]){
    for(int i = 1; i < standard_row; i++)  Shift_Right_Rotation(input[i], i);
}

/* ------------------------------- MixColumn ------------------------------- */

// get modular value using for Galois field multiply
uint8_t calc_mod(uint8_t input){
    uint8_t result = 0;
    for(int i = 0; i < standard_column; i++)  if((input >> i) & 0x1)  result ^= (0x1b << i);
    return result;
}

// multiply in Galois field (mod x^8 + x^4 + x^3 + x + 1) 
uint8_t multiply(uint8_t a, uint8_t b){
    uint16_t sum = 0;
    uint8_t mod = 0;
    for(int i = 0; i < standard_column; i++){
        if(b >> i & 0x1){
            sum ^= (a << i);
            if(i != 0)  mod ^= calc_mod(a >> (8 - i));
        }
    }
    return sum ^ mod;
}

void Mul_Matrix(uint8_t (*input)[standard_column], int column, int type){
    uint8_t result[standard_column];
    uint8_t tmp;
    for(int i = 0; i < standard_row; i++){
        tmp = 0;
        for(int j = 0; j < standard_column; j++)  tmp ^= multiply(input[j][column], Mix_columns_Array[type][i][j]);
        result[i] = tmp;
    }
    for(int i = 0; i < standard_row; i++)  input[i][column] = result[i];
}

void Mix_columns(uint8_t (*input)[standard_column], int type){
    for(int i = 0; i < standard_column; i++)  Mul_Matrix(input, i, type);
}

/* ------------------------------- AddRoundKey ------------------------------- */

void Add_Round_Key(uint8_t (*input)[standard_column], uint8_t (*round_key)[standard_column]){
    for(int i = 0; i < standard_row; i++)  for(int j = 0; j < standard_column; j++)  input[i][j] = round_key[i][j] ^ input[i][j];
}

/* ------------------------------- Key Scheduling ------------------------------- */

void create_round_key(int round, int key_block, uint8_t (*input)[key_block], uint8_t output[standard_row][key_block]){
    /*make standard*/
    for(int i = 0; i < standard_row - 1; i++){
        if(i == 0)  output[i][0] = S_BOX_Array[0][input[i+1][key_block - 1]] ^ Rcon[round] ^ input[i][0];
        else    output[i][0] = S_BOX_Array[0][input[i+1][key_block - 1]] ^ input[i][0];
    }
    output[standard_row - 1][0] = S_BOX_Array[0][input[0][key_block - 1]] ^ input[standard_row - 1][0];
    for(int i = 1; i < key_block; i++)  for(int j = 0; j < standard_row; j++)   output[j][i] = output[j][i-1] ^ input[j][i];
}

void Key_Scheduling(int round, int key_block, uint8_t (*cipher_key)[key_block], uint8_t (*round_key)[standard_row][key_block]){
    for(int i = 0; i < standard_row; i++)    for(int j = 0; j < key_block; j++)   round_key[0][i][j] = cipher_key[i][j];
    for(int i = 0; i < round; i++) create_round_key(i, key_block, round_key[i], round_key[i+1]);
}

/* ------------------------------- encrypt and decrypt function ------------------------------- */

void encrypt(uint8_t (*plaintext)[], uint8_t (*round_key)[standard_row][standard_column], int round){
    Add_Round_Key(plaintext, round_key[0]);
    for(int i = 1; i < round; i++){
        SubBytes(plaintext, 0);
        Shift_Row(plaintext);
        Mix_columns(plaintext, 0);
        Add_Round_Key(plaintext, round_key[i]);
    }
    SubBytes(plaintext, 0);
    Shift_Row(plaintext);
    Add_Round_Key(plaintext, round_key[round]);
}

void decrypt(uint8_t (*ciphertext)[], uint8_t (*round_key)[standard_row][standard_column], int round){
    Add_Round_Key(ciphertext, round_key[round]);
    Inv_Shift_Row(ciphertext);
    SubBytes(ciphertext, 1);
    for(int i = round - 1; i > 0; i--){
        Add_Round_Key(ciphertext, round_key[i]);
        Mix_columns(ciphertext, 1);
        Inv_Shift_Row(ciphertext);
        SubBytes(ciphertext, 1);
    }
    Add_Round_Key(ciphertext, round_key[0]);
}

/* ------------------------------- round_key seperate ------------------------------- */

void seperate_round_key(int column, uint8_t (*output)[standard_row][standard_column], uint8_t (*input)[standard_row][column], int bit){
    if(bit == 128){
        for(int i = 0; i < 11; i++){
            for(int j = 0; j < standard_row; j++){
                for(int k = 0; k < 4; k++)  output[i][j][k] = input[i][j][k];
            }
        }
    }
    else if(bit == 192){
        for(int k = 0; k < 9; k++){
            for(int i = 0; i < standard_row; i++){
                for(int j = 0; j < 6; j++){
                    if(k % 2 == 0){
                        if(j < 4)   output[k + (int)(k/2)][i][j] = input[k][i][j];
                        else    output[k + (int)(k/2)+1][i][j-4] = input[k][i][j];
                    }else{
                        if(j < 2)   output[k + (int)(k/2)][i][j+2] = input[k][i][j];
                        else    output[k + (int)(k/2)+1][i][j-2] = input[k][i][j];
                    }
                }
            }
        }
    }
    else if(bit == 256){
        for(int i = 0; i < 8; i++){
            for(int j = 0; j < standard_row; j++){
                for(int k = 0; k < 4; k++){
                    output[i*2][j][k] = input[i][j][k];
                    output[i*2+1][j][k] = input[i][j][k+4];
                }
            }
        }
    }
}

/* ------------------------------- AES 128,192,256bit ------------------------------- */

void AES_128bit(char *plaintext, uint8_t key[standard_row * 4]){
    printf("\n----------------- AES 128bit ------------------------\n");
    uint8_t Text[standard_row][standard_column];
    uint8_t cipher_key[standard_row][4];
    set_text(Text, plaintext);
    set_key(4, cipher_key, key);
    uint8_t G_round_key[11][4][4] = {0};
    uint8_t round_key[11][4][4] = {0};
    Key_Scheduling(10, 4, cipher_key, G_round_key);
    seperate_round_key(4, round_key, G_round_key, 128);

    printf("plain text : ");
    print_stream(standard_row, standard_column, Text);
    
    encrypt(Text, round_key, 10);
    printf("\nencrypted text : ");
    print_text(standard_row, standard_column, Text);
    
    decrypt(Text, round_key, 10);
    printf("\ndecrypted text : ");
    print_text(standard_row, standard_column, Text);
}

void AES_192bit(char *plaintext, uint8_t key[standard_row * 6]){
    printf("\n----------------- AES 192bit ------------------------\n");
    uint8_t Text[standard_row][standard_column];
    uint8_t cipher_key[standard_row][6];
    set_text(Text, plaintext);
    set_key(6, cipher_key, key);
    uint8_t G_round_key[9][4][6] = {0};
    uint8_t round_key[13][4][4] = {0};                      
    Key_Scheduling(8, 6, cipher_key, G_round_key);
    seperate_round_key(6, round_key, G_round_key, 192);

    printf("plain text : ");
    print_text(standard_row, standard_column, Text);

    encrypt(Text, round_key, 12);
    printf("\nencrypted text : ");
    print_stream(standard_row, standard_column, Text);

    decrypt(Text, round_key, 12);
    printf("\ndecrypted text : ");
    print_text(standard_row, standard_column, Text);
}

void AES_256bit(char *plaintext, uint8_t key[standard_row * 8]){
    printf("\n----------------- AES 256bit ------------------------\n");
    uint8_t Text[standard_row][standard_column];
    uint8_t cipher_key[standard_row][8];
    set_text(Text, plaintext);
    set_key(8, cipher_key, key);
    uint8_t G_round_key[8][4][8] = {0};
    uint8_t round_key[16][4][4] = {0};
    Key_Scheduling(7, 8, cipher_key, G_round_key);
    seperate_round_key(8, round_key, G_round_key, 256);

    printf("plain text : ");
    print_text(standard_row, standard_column, Text);

    encrypt(Text, round_key, 14);
    printf("\nencrypted text : ");
    print_stream(standard_row, standard_column, Text);

    decrypt(Text, round_key, 14);
    printf("\ndecrypted text : ");
    print_text(standard_row, standard_column, Text);
}