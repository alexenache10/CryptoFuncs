#pragma once

#include <time.h>
#include <stdlib.h>

#define SBOX_SIZE 256


void shuffle_sbox(unsigned char sbox[SBOX_SIZE][SBOX_SIZE]);
void generateKeystream(unsigned char* keystream, int keystream_length, unsigned char* seed, int seed_length);
void generateSbox(unsigned char sbox[256][256]);