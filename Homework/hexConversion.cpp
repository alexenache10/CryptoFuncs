#define _CRT_SECURE_NO_WARNINGS
#include "hexConversion.h"
#include <iostream>
#include <math.h>
#include <stdlib.h>
#include <stdio.h>

void assignValues(int* a, char b)
{
    if (b >= 'A' && b <= 'Z')
    {
        *a = b - 'A' + 10;
    }
    else if (b >= 'a' && b <= 'z')
    {
        *a = b - 'a' + 10;
    }
    else
    {
        *a = b - '0';
    }
}

void hexToBinary(unsigned char** result, const unsigned char* sequence, int len, int *output_len)
{
    int first, second;
    int amount = (len % 2 == 0) ? len / 2 + 1 : len / 2 + 2; // daca sirul initial are dimensiune impara, vom avea nevoie de un octet in plus pentru sirul convertit
  
    *result = new unsigned char[amount];
    (*result)[amount-1] = '\0';
    int count = 0;
    for (int i = 0; i < len; i = i + 2)
    {
        assignValues(&first, sequence[i]);
        assignValues(&second, sequence[i + 1]);

        (*result)[count] = (unsigned char)first;
        
        if (sequence[i+1] == '\0')
        {
            break;
        }
        (*result)[count] = (*result)[count] << 4;
        (*result)[count] += (unsigned char)second;
        count++;
    }

    *output_len = amount;
 
}
void ASCIItoBIN_print(unsigned char* result, int output_len)
{
    printf("Printing memory content...\n");
    printf("> ");
    for (int i = 0; i < output_len-1; i++)
    {
        printf("0x%.02x ", result[i]);
    }
    printf("\n");
}

char translate(int val) {
    if (val >= 0 && val <= 9)
        return val + '0';
    else
        return val - 10 + 'A';
}

void binaryToHex(const char* binary_file, const char* output_file)
{
    FILE* input_ptr = fopen(binary_file, "rb");
    if (input_ptr == NULL) {
        fprintf(stderr, "Couldn't open %s file!", binary_file);
        return;
    }

    fseek(input_ptr, 0, SEEK_END);
    int len = ftell(input_ptr);
    rewind(input_ptr);

    unsigned char* content = new unsigned char[len];
    fread(content, sizeof(unsigned char), len, input_ptr);
    fclose(input_ptr);

    FILE* output_ptr = fopen(output_file, "w");
    if (output_ptr == NULL) {
        fprintf(stderr, "Couldn't open %s file!", output_file);
        delete[] content; 
        return;
    }

    for (int i = 0; i < len; i++)
    {
        int first_val = content[i] >> 4;
        int second_val = content[i] & 0xF;

        fputc(translate(first_val), output_ptr);
        fputc(translate(second_val), output_ptr);
    }

    fclose(output_ptr);
    delete[] content; 
}