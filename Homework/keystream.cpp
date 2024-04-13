#include "keystream.h"
#include "openssl/rand.h"

void shuffle_sbox(unsigned char sbox[SBOX_SIZE][SBOX_SIZE])
{

    for (int i = 0; i < SBOX_SIZE; i++)
        for (int j = 0; j < SBOX_SIZE; j++)
        {
            unsigned char aux = sbox[(rand() % (i * 2 + 11) + rand() % (i + j * 2 + 2) + rand() % 256) % 256][(rand() % (256 - i + j) + rand() % (j + i * 2 + 111)) % 256];
            sbox[(rand() % (i * 2 + 11) + rand() % (i + j * 2 + 2) + rand() % 256) % 256][(rand() % (256 - i + j) + rand() % (j + i * 2 + 111)) % 256] = sbox[(rand() % (j + 5) + rand() % (i * j + 1)) % 256][((i + 1) * 2 + j * rand()) % 256];
            sbox[(rand() % (j + 5) + rand() % (i * j + 1)) % 256][((i + 1) * 2 + j * rand()) % 256] = aux;
        }
}

void generateKeystream(unsigned char* keystream, int keystream_length, unsigned char* seed, int seed_length) {
    unsigned char sbox[SBOX_SIZE][SBOX_SIZE];
    srand(*reinterpret_cast<unsigned int*>(seed)); // setam operatia de random sa functioneze in functie de seedul oferit
    
    generateSbox(sbox);

    shuffle_sbox(sbox); // amestecam s-boxul - confuzie

    unsigned char state = seed[0];
    for (int i = 0; i < keystream_length; i++) {
        unsigned char temp = sbox[state][seed[i % seed_length]]; // difuzie
        keystream[i] = temp ^ state;
        state = (state << 3) | (state >> 4) | ((state & (i << 5) & rand() % 0xFF));
        state = (state + seed[i % seed_length]) % SBOX_SIZE;
    }
}


void generateSbox(unsigned char sbox[256][256]) {
    unsigned char seed[16];
    RAND_bytes(seed, sizeof(seed));
    RAND_seed(seed, sizeof(seed));

    for (int i = 0; i < 256; ++i) {
        for (int j = 0; j < 256; ++j) {
            RAND_bytes(&sbox[i][j], sizeof(unsigned char));
        }
    }
}