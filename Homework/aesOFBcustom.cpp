#define _CRT_SECURE_NO_WARNINGS

#pragma warning(disable:4996)

#include <iostream>
#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include "aesOFBcustom.h"
#include <openssl/aes.h>

// folosim o singura functie atat pentru criptare cat si decriptare deoarece asa opereaza modul de lucru OFB + proprietatile matematice ale XOR-ului
void aes_encryption_ofb(unsigned char* IV, unsigned char* key, int key_len, unsigned char* plain_text, int text_len, unsigned char** encrypted)
{
    AES_KEY aes_key;
    AES_set_encrypt_key(key, key_len * 8, &aes_key);

    *encrypted = new unsigned char[text_len];

    unsigned char current_init[16];
    unsigned char encrypted_block[16];

    memcpy(current_init, IV, 16);

    int num_blocks = (text_len % 16 == 0) ? text_len / 16 : text_len / 16 + 1;
    for (int i = 0; i < num_blocks; i++)
    {
        AES_encrypt(current_init, current_init, &aes_key); 
        int block_size = (i == text_len / 16) ? text_len % 16 : 16; // daca am ajuns la final si inca suntem in loop inseamna ca mai avem cativa octeti ce nu sunt multiplu de 16
        unsigned char current_block[16];
        memcpy(current_block, plain_text + i * 16, block_size);

        // adunam 5 la primul octet disponibil in care incape din blocul de 16 octeti
        for (int j = 0; j < block_size; j++)
        {
            if (!(current_init[j] >= 250)) 
            {
                current_init[j]+=5;
                break;
            }
        }

        for (int j = 0; j < block_size; j++)
        {
            //current_init[j] += 5;
            encrypted_block[j] = current_block[j] ^ current_init[j];
        }
        memcpy(*encrypted + i * 16, encrypted_block, block_size);
        memcpy(IV, current_init, 16);
    }
}