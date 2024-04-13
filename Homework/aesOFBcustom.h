#pragma once

void aes_encryption_ofb(unsigned char* IV, unsigned char* key, int key_len, unsigned char* plain_text, int text_len, unsigned char** encrypted);
