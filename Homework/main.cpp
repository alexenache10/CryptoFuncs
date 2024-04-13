#define _CRT_SECURE_NO_WARNINGS

#pragma warning(disable : 4996) //doar pentru versiunea 3.0 a OpenSSL

#include <string>
#include <stdio.h>
#include "hexConversion.h"
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <iostream>
#include "aesOFBcustom.h"
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <map>
#include "keystream.h"


#define AES_BLOCKSIZE 16

using namespace std;

typedef struct Packet
{
    ASN1_OCTET_STRING* EncMessage;
    ASN1_UTCTIME* TimeStamp;
    ASN1_PRINTABLESTRING* AuthData;
    ASN1_OCTET_STRING* Tag;
    ASN1_OCTET_STRING* Algoritm;
};

ASN1_SEQUENCE(Packet) = {
    ASN1_SIMPLE(Packet, EncMessage, ASN1_OCTET_STRING),
    ASN1_SIMPLE(Packet, TimeStamp, ASN1_UTCTIME),
    ASN1_SIMPLE(Packet, AuthData, ASN1_PRINTABLESTRING),
    ASN1_SIMPLE(Packet, Tag, ASN1_OCTET_STRING),
    ASN1_SIMPLE(Packet, Algoritm, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(Packet);

DECLARE_ASN1_FUNCTIONS(Packet);
IMPLEMENT_ASN1_FUNCTIONS(Packet);

typedef struct EMBEDDED_KEY
{
    BIGNUM* Numar_1;
    BIGNUM* Numar_2;
    BIGNUM* Numar_3;
    BIGNUM* Numar_4;
    BIGNUM* Numar_5;
} EMBEDDED_KEY;

typedef struct Master_key
{
    ASN1_PRINTABLESTRING* CommonName;
    ASN1_PRINTABLESTRING* Subject;
    ASN1_INTEGER* Key_ID;
    EMBEDDED_KEY* key;
} Master_key;

ASN1_SEQUENCE(EMBEDDED_KEY) = {
    ASN1_SIMPLE(EMBEDDED_KEY, Numar_1, BIGNUM),
    ASN1_SIMPLE(EMBEDDED_KEY, Numar_2, BIGNUM),
    ASN1_SIMPLE(EMBEDDED_KEY, Numar_3, BIGNUM),
    ASN1_SIMPLE(EMBEDDED_KEY, Numar_4, BIGNUM),
    ASN1_SIMPLE(EMBEDDED_KEY, Numar_5, BIGNUM),
} ASN1_SEQUENCE_END(EMBEDDED_KEY);

DECLARE_ASN1_FUNCTIONS(EMBEDDED_KEY);
IMPLEMENT_ASN1_FUNCTIONS(EMBEDDED_KEY);

ASN1_SEQUENCE(Master_key) = {
    ASN1_SIMPLE(Master_key, CommonName, ASN1_PRINTABLESTRING),
    ASN1_SIMPLE(Master_key, Subject, ASN1_PRINTABLESTRING),
    ASN1_SIMPLE(Master_key, Key_ID, ASN1_INTEGER),
    ASN1_SIMPLE(Master_key, key, EMBEDDED_KEY),
} ASN1_SEQUENCE_END(Master_key);

DECLARE_ASN1_FUNCTIONS(Master_key);
IMPLEMENT_ASN1_FUNCTIONS(Master_key);


class Person
{
private:
    std::string name;
    unsigned char* packet;
    int len;
public:
    //std::map<std::string, std::string> keyPairs; // nume_persoana:cheie
    string getName() { return name; }
    unsigned char* getPacket() { return packet; }
    void setPacket(int len, unsigned char* new_packet) {
        if (packet != nullptr)
            delete[] packet;
        this->len = len;
        packet = new unsigned char[len];
        memcpy(packet, new_packet, len);
    }
    Person(std::string name) { this->name = name; packet = nullptr; len = 0; }
    void sendPacket(Packet** packet, Person& dest);
    void printDetails(unsigned char* key,unsigned char* IV, unsigned char* nonce); // functie de convertire din Base64 in clar, apoi realizare d2i (creare structura ASN1) si afisare campuri
   // void assign_pair(std::string name, std::string key);
    void  configurePacket(Packet** packet, unsigned char* key, unsigned char* IV, unsigned char* nonce);
};

unsigned char sBox[] = {
    0x63, 0x21,
};


unsigned char* base64_decode(const unsigned char* input, int length, int* output_length) {
    BIO* bio, * b64;
    unsigned char*  buffer = new unsigned char[length];
    memset(buffer, 0, length);
    bio = BIO_new_mem_buf(input, length);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); 
    *output_length = BIO_read(bio, buffer, length);
    BIO_free_all(bio);

    return buffer;
}

unsigned char* base64_encode(const unsigned char* input, int length, int* output_length) {
    BIO* bio, * b64;
    BUF_MEM* bufferPtr;
    bio = BIO_new(BIO_s_mem());
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); 
    bio = BIO_push(b64, bio);

    BIO_write(bio, input, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    *output_length = bufferPtr->length;

    unsigned char* output = new unsigned char[*output_length];
    memcpy(output, bufferPtr->data, *output_length);

    BIO_free_all(bio);

    return output;
}



void Person::sendPacket(Packet** packet, Person& dest)
{
    // serializam pachetul si il codificam base64 apoi
    ASN1_STRING_set((*packet)->AuthData, (unsigned char*)dest.name.c_str(), dest.name.size());
    unsigned char* ber_info, * my_ber;
    int len = i2d_Packet(*packet, NULL);
    ber_info = (unsigned char*)OPENSSL_malloc(len);
    my_ber = ber_info;
    i2d_Packet(*packet, &my_ber);


    int output_len;
    unsigned char* encoded_base64 = base64_encode(ber_info, len, &output_len);
    
    dest.setPacket(output_len, encoded_base64);

  
}

void encrypt_aes_gcm(unsigned char** encrypted, unsigned char** tag, const unsigned char* key, const unsigned char* IV, const unsigned char* message, int message_length, int* encrypted_length, int* tag_length) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit(ctx, EVP_aes_256_gcm(), key, IV);
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    *encrypted = new unsigned char[message_length + EVP_CIPHER_block_size(EVP_aes_256_gcm())];

    int len;
    EVP_EncryptUpdate(ctx, *encrypted, &len, message, message_length);

    *encrypted_length = len;

    EVP_EncryptFinal(ctx, *encrypted + len, &len);
    *encrypted_length += len;

    *tag = new unsigned char[EVP_GCM_TLS_TAG_LEN];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, EVP_GCM_TLS_TAG_LEN, *tag);
    *tag_length = EVP_GCM_TLS_TAG_LEN;

    EVP_CIPHER_CTX_free(ctx);
}

void encrypt_chacha20(unsigned char** encrypted, const unsigned char* key, const unsigned char* nonce, const unsigned char* message, int message_length, int* encrypted_length, int* taglen, unsigned char** tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit(ctx, EVP_chacha20(), key, nonce);

    *encrypted = new unsigned char[message_length + EVP_CIPHER_block_size(EVP_chacha20())];
    int len;
    EVP_EncryptUpdate(ctx, *encrypted, &len, message, message_length);

    *encrypted_length = len;
    EVP_EncryptFinal(ctx, *encrypted + len, &len);
    *encrypted_length += len;

    *tag = new unsigned char[EVP_GCM_TLS_TAG_LEN];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, EVP_CHACHAPOLY_TLS_TAG_LEN, *tag);
    *taglen = EVP_CHACHAPOLY_TLS_TAG_LEN;

    EVP_CIPHER_CTX_free(ctx);
}

void decrypt_aes_gcm(unsigned char** decrypted, const unsigned char* key, const unsigned char* IV, const unsigned char* message, int message_length, const unsigned char* tag, int tag_length, int* decrypted_length) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit(ctx, EVP_aes_256_gcm(), key, IV);
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    *decrypted = new unsigned char[message_length+1];

    int len;
    EVP_DecryptUpdate(ctx, *decrypted, &len, message, message_length);

    *decrypted_length = len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_length, (void*)tag);

    if (!EVP_DecryptFinal(ctx, *decrypted + len, &len)) {
        delete[] * decrypted;
        *decrypted = nullptr;
        *decrypted_length = 0;
    }
    else {
        *decrypted_length += len;
    }

    EVP_CIPHER_CTX_free(ctx);
}

void decrypt_chacha20(unsigned char** decrypted, const unsigned char* key, const unsigned char* nonce, const unsigned char* message, int message_length, int* decrypted_length) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit(ctx, EVP_chacha20(), key, nonce);

    *decrypted = new unsigned char[message_length];
    int len;
    EVP_DecryptUpdate(ctx, *decrypted, &len, message, message_length);

    *decrypted_length = len;
    EVP_DecryptFinal(ctx, *decrypted + len, &len);
    *decrypted_length += len;

    EVP_CIPHER_CTX_free(ctx);
}

void Person::printDetails(unsigned char* key, unsigned char* IV, unsigned char* nonce)
{
    // convertim la integer din DER inapoi
    int output;
    unsigned char* decoded = base64_decode(this->packet, this->len, &output);
    const unsigned char* ber_input = decoded;
    Packet* decoded_info = d2i_Packet(NULL, &ber_input, output);
    if (decoded_info == nullptr)
    {
        printf("Error trying to decode back to integer from DER!");
        exit(0);
    }

    unsigned char* decrypted = nullptr;
    int declen;
    if (strcmp((char*)ASN1_STRING_get0_data(decoded_info->Algoritm), "aes") == 0)
    {
        decrypt_aes_gcm(&decrypted, key, IV, ASN1_STRING_get0_data(decoded_info->EncMessage), decoded_info->EncMessage->length, ASN1_STRING_get0_data(decoded_info->Tag), decoded_info->Tag->length, &declen);
    }
    else
    {

        decrypt_chacha20(&decrypted, key, nonce, ASN1_STRING_get0_data(decoded_info->EncMessage), decoded_info->EncMessage->length, &declen);
    }
  
 
    printf("---- PRINTING FOR %s RECEIVED PACKAGE --------\n", this->getName().c_str());
    if (decrypted != nullptr)
    {
        printf("DECRYPTED MESSAGE: ");
        for (int i = 0; i < declen; i++)
            printf("%c", decrypted[i]);
        printf("\n");
    }
    else
        printf("COULDN'T DECRYPT MESSAGE, CRYPTED: %s\n", ASN1_STRING_get0_data(decoded_info->EncMessage));

    printf("TIME_STAMP: %s\n", ASN1_STRING_get0_data(decoded_info->TimeStamp));
    printf("AUTH DATA: %s\n", ASN1_STRING_get0_data(decoded_info->AuthData));
    printf("TAG: %s\n", ASN1_STRING_get0_data(decoded_info->Tag));
    printf("ALGORITHM: %s\n", ASN1_STRING_get0_data(decoded_info->Algoritm));

    delete[] decoded;
    delete[] decrypted;
    Packet_free(decoded_info);
}
//
//void Person::assign_pair(std::string name, std::string key)
//{
//    //this->keyPairs[name] = key;
//}



void Person::configurePacket(Packet** packet, unsigned char* key, unsigned char* IV, unsigned char* nonce)
{
    std::string algorithm;
    printf("> Configuring packet for %s...\n", this->getName().c_str());
    printf("Choose Algorithm to use to encrypt the message you'll send (type aes / chacha): ");
    std::cin >> algorithm;
    std::cin.ignore();
    ASN1_OCTET_STRING_set((*packet)->Algoritm, (unsigned char*)algorithm.c_str(), algorithm.size());


    printf("Introduce the message that you want to send: ");
    std::string message;
    std::getline(std::cin, message);

    unsigned char* encrypted = nullptr;
    unsigned char* tag = nullptr;
    int taglen;
    int len;
    if (algorithm == "aes") {
        encrypt_aes_gcm(&encrypted, &tag, key, IV, (unsigned char*)message.c_str(), message.size(), &len, &(taglen));
    
    }
    else if (algorithm == "chacha") {
        encrypt_chacha20(&encrypted, key, nonce, (unsigned char*)message.c_str(), message.size(), &len, &taglen, &tag);

    }
    else {
        fprintf(stderr, "Invalid algorithm specified!\n");
        return;
    }

    ASN1_OCTET_STRING_set((*packet)->Tag, tag, (taglen));
    ASN1_OCTET_STRING_set((*packet)->EncMessage, encrypted, len);

    time_t rawtime;
    time(&rawtime);

    ASN1_UTCTIME_set((*packet)->TimeStamp, rawtime);

}


bool is_prime(unsigned long long int n) {
    BIGNUM* bn = BN_new();
    BN_set_word(bn, n);

    int result = BN_is_prime(bn, BN_prime_checks, NULL, NULL, NULL);
    bool bool_result = (result == 1) ? true : false;

    BN_free(bn);
    return bool_result;
}

unsigned long long int generate_prime_between(unsigned long long int lower, unsigned long long int upper) {
    unsigned long long int generated;
    do {
        RAND_bytes(reinterpret_cast<unsigned char*>(&generated), sizeof(generated));
        generated %= (upper - lower + 1);
        generated += lower;
    } while (!is_prime(generated));
    return generated;
}

unsigned long long int generate_odd() {
    unsigned long long int n;
    do {
        RAND_bytes(reinterpret_cast<unsigned char*>(&n), sizeof(unsigned long long int));
    } while (n == 0 || n % 2 == 0);
    return n;
}



// varianta mai simpla decat calcul manual folosind algoritmul extins al lui Euclid
unsigned long long int generate_fourth(unsigned long long int first, unsigned long long int second, unsigned long long int third) {
    unsigned long long int exp = (first - 1ULL) * (second - 1ULL);

    BIGNUM* exp_bn = BN_new();
    BIGNUM* third_bn = BN_new();
    BIGNUM* inv = BN_new();
    BN_CTX* ctx = BN_CTX_new();

    BN_set_word(third_bn, third);
    BN_set_word(exp_bn, exp);

    BN_mod_inverse(inv, third_bn, exp_bn, ctx);

    BN_free(exp_bn);
    BN_free(third_bn);
    BN_CTX_free(ctx);
    unsigned long long int result = BN_get_word(inv);
    BN_free(inv);
    return result;
}

unsigned long long int generate_fifth(unsigned long long int first, unsigned long long int second) {
    return first * second;
}

void printASNstructure(Master_key* master) {
    printf("> Printing ASN1 Master_key structure...\n");
    printf("CommonName: %s\n", master->CommonName->data);
    printf("Subject: %s\n", master->Subject->data);
    printf("Key_ID: %d\n", ASN1_INTEGER_get(master->Key_ID));
    printf("> Printing ASN1 EMBEDDED KEY structure from Master_key...\n");
    printf("Numar_1: %llu\n", BN_get_word(master->key->Numar_1));
    printf("Numar_2: %llu\n", BN_get_word(master->key->Numar_2));
    printf("Numar_3: %llu\n", BN_get_word(master->key->Numar_3));
    printf("Numar_4: %llu\n", BN_get_word(master->key->Numar_4));
    printf("Numar_5: %llu\n", BN_get_word(master->key->Numar_5));
}

Master_key* createMasterKey() {
    Master_key* masterKey = Master_key_new();
    if (!masterKey) {
        fprintf(stderr, "Error when allocating memory for masterKey structure!\n");
        return NULL;
    }

    char commonName[256];
    printf("> Introduce a common name for CommonName: ");
    scanf("%s", commonName);
    masterKey->CommonName = ASN1_PRINTABLESTRING_new();
    if (!masterKey->CommonName) {
        fprintf(stderr, "Error when allocating memory for CommonName!\n");
        Master_key_free(masterKey);
        return NULL;
    }
    ASN1_STRING_set(masterKey->CommonName, commonName, strlen(commonName));

    char subject[256];
    printf("> Introduce a common name for Subject: ");
    scanf("%s", subject);
    masterKey->Subject = ASN1_PRINTABLESTRING_new();
    if (!masterKey->Subject) {
        fprintf(stderr, "Error when allocating memory for Subject!\n");
        Master_key_free(masterKey);
        return NULL;
    }
    ASN1_STRING_set(masterKey->Subject, subject, strlen(subject));

    int ID;
    printf("> Introduce an integer for the Key_ID: ");
    scanf("%d", &ID);

    masterKey->Key_ID = ASN1_INTEGER_new();
    if (!masterKey->Key_ID) {
        fprintf(stderr, "Error when allocating memory for ID!\n");
        Master_key_free(masterKey);
        return NULL;
    }
    ASN1_INTEGER_set(masterKey->Key_ID, ID);

    masterKey->key = EMBEDDED_KEY_new();
    if (!masterKey->key) {
        fprintf(stderr, "Error when allocating memory for EMBEDDED KEY!\n");
        Master_key_free(masterKey);
        return NULL;
    }
    masterKey->key->Numar_1 = BN_new();
    masterKey->key->Numar_2 = BN_new();
    masterKey->key->Numar_3 = BN_new();
    masterKey->key->Numar_4 = BN_new();
    masterKey->key->Numar_5 = BN_new();

    BN_set_word(masterKey->key->Numar_1, generate_prime_between(1ULL << 20, 1ULL << 31));
    BN_set_word(masterKey->key->Numar_2, generate_prime_between(1ULL << 20, 1ULL << 31));
    BN_set_word(masterKey->key->Numar_3, generate_odd());
    BN_set_word(masterKey->key->Numar_4, generate_fourth(BN_get_word(masterKey->key->Numar_1), BN_get_word(masterKey->key->Numar_2), BN_get_word(masterKey->key->Numar_3)));
    BN_set_word(masterKey->key->Numar_5, generate_fifth(BN_get_word(masterKey->key->Numar_1), BN_get_word(masterKey->key->Numar_2)));

    return masterKey;
}

void assignKey(unsigned char** key, const char* filename, int* len)
{
    FILE* file = fopen(filename, "r");
    fseek(file, 0, SEEK_END);

    *len = ftell(file);
    if (!(*len == 16 || *len == 32 || *len == 24))
    {
        fclose(file);
        fprintf(stderr, "Wrong amount of bits for the AES-KEY!");
        exit(EXIT_SUCCESS);
    }

    rewind(file);
    *key = new unsigned char[*len + 1];
    (*key)[*len] = '\0';
    fread(*key, sizeof(unsigned char), *len, file);

    fclose(file);
}

void assignPlain(unsigned char** content, int* len, const char* filename)
{
    FILE* fileptr = fopen(filename, "r");

    fseek(fileptr, 0, SEEK_END);
    *len = ftell(fileptr);
    rewind(fileptr);

    *content = new unsigned char[*len + 1];
    (*content)[*len] = '\0';
    fread(*content, sizeof(unsigned char), *len, fileptr);


    fclose(fileptr);

}

void assignMode(string& mode)
{
    printf("> Type enc for encryption or dec for decryption: ");
    cin >> mode;
}

Packet* generatePacket()
{
    Packet* first_packet = Packet_new();
    first_packet->Algoritm = ASN1_OCTET_STRING_new();
    first_packet->AuthData = ASN1_PRINTABLESTRING_new();
    first_packet->EncMessage = ASN1_OCTET_STRING_new();
    first_packet->Tag = ASN1_OCTET_STRING_new();
    first_packet->TimeStamp = ASN1_UTCTIME_new();
    return first_packet;
}
void test_communication()
{

    Person first_person("Alice");
    Person second_person("Bob");
    Person third_person("Charlie");

    unsigned char* k_a = new unsigned char[32];
    unsigned char* k_b = new unsigned char[32];
    unsigned char* k_c = new unsigned char[32];
    RAND_bytes(k_a, 32);
    RAND_bytes(k_b, 32);
    RAND_bytes(k_c, 32);

   // testam comunicatia ceruta
    unsigned char* IV = new unsigned char[12];
    RAND_bytes(IV, 12);
    unsigned char* nonce = new unsigned char[8];
    RAND_bytes(nonce, 8);

    Packet* alice_to_bob = generatePacket(); // k_a
    Packet* alice_to_charlie = generatePacket(); // k_b
    Packet* bob_to_charlie = generatePacket(); // k_c

  

    // TESTING...
    // 1. Alice catre Bob si Charlie
    first_person.configurePacket(&alice_to_bob, k_a, IV, nonce);
    first_person.configurePacket(&alice_to_charlie, k_b, IV, nonce);

    first_person.sendPacket(&alice_to_bob, second_person); 
    first_person.sendPacket(&alice_to_charlie, third_person);
    second_person.printDetails(k_a, IV, nonce);
    third_person.printDetails(k_b, IV, nonce);

    // 2. Bob transmite ce a primit de la Alice, lui Charlie, adica pachetul acela
     // Charlie primeste pachetul lui Bob primit de la Alice, insa nu poate decripta mesajul! El nu stie cheia de comunicare simetrica dintre Alice si Bob
    // Asadar, nu vom afisa un mesaj in clar, ci doar unul criptat
    second_person.sendPacket(&alice_to_bob, third_person);
    third_person.printDetails(k_c, IV, nonce);

    // 3. Charlie raspunde lui Alice
    Packet* charlie_to_alice = generatePacket();
    Packet* charlie_to_bob = generatePacket();
    third_person.configurePacket(&charlie_to_alice, k_b, IV, nonce);
    third_person.configurePacket(&charlie_to_bob, k_c, IV, nonce);
    third_person.sendPacket(&charlie_to_alice, first_person);
    third_person.sendPacket(&charlie_to_bob, second_person);

    first_person.printDetails(k_b, IV, nonce);
    second_person.printDetails(k_c, IV, nonce);



    delete[] IV;
    delete[] nonce;
    delete[] k_a;
    delete[] k_b;
    delete[] k_c;
}

void conversions()
{
    unsigned char sentence[128];
    printf("> Introduce the hex string: ");
    scanf("%s", sentence);

    unsigned char* result = nullptr;
    int len = strlen((char*)sentence);
    int output_len;
    hexToBinary(&result, sentence, len, &output_len); // ne permitem sa folosim strlen deoarece suntem siguri ca lucram doar cu informatie ASCII
    ASCIItoBIN_print(result, output_len);

    FILE* fileptr = fopen("binarycontent.bin", "wb");
    fwrite(result, sizeof(unsigned char), output_len - 1, fileptr);

    binaryToHex("binarycontent.bin", "textcontent.txt");
    fclose(fileptr);
    delete[] result;
}

void master_key_struct_usage()
{
    Master_key* master = createMasterKey();
    printASNstructure(master);

    unsigned char* ber_info, * myber; // serializare
    int len = i2d_Master_key(master, NULL);
    ber_info = (unsigned char*)OPENSSL_malloc(len);
    if (ber_info == nullptr)
        fprintf(stderr, "OpenSSL malloc Error Occur:(\n");
    myber = ber_info;

    i2d_Master_key(master, &myber);
    FILE* myOut = fopen("out.bin", "wb");
    fwrite(ber_info, len, 1, myOut);
    OPENSSL_free(ber_info);
    Master_key_free(master);
    fclose(myOut);

}

void test_aes_ofb(char* IV)
{
    unsigned char* content = nullptr;
    unsigned char* key = nullptr;
    string mode;
    int dimension;
    int len;
    assignKey(&key, "file.key", &dimension);
    assignPlain(&content, &len, "text.txt"); // continutul pe care il criptam / decriptam se afla in fisierul text.txt
    assignMode(mode);

    if (mode == "enc")
    {
        unsigned char* encrypted = nullptr;

        aes_encryption_ofb((unsigned char*)IV, key, dimension, content, len, &encrypted);
        FILE* f = fopen("aesout.txt", "w");
        fwrite(encrypted, sizeof(unsigned char), len, f);
    
        fclose(f);
        delete[] encrypted;
    }
    else
    {
        unsigned char* decrypted = nullptr;

        aes_encryption_ofb((unsigned char*)IV, key, dimension, content, len, &decrypted);

        FILE* f = fopen("aesout.txt", "w");
        fwrite(decrypted, sizeof(unsigned char), len, f);

        fclose(f);
        delete[] decrypted;
    }

    delete[] content;
    delete[] key;

}

void keystream_gen()
{
    const int keystream_length = 16;
    const int seed_length = 16;

    unsigned char seed[seed_length] = {
        0x01, 0x23, 0x45, 0x67,
        0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98,
        0x76, 0x54, 0x32, 0x10
    };

    unsigned char keystream[keystream_length];

    generateKeystream(keystream, keystream_length, seed, seed_length);

    printf("Keystream generated: ");
    for (int i = 0; i < keystream_length; i++)
        printf("%.02x ", keystream[i]);
}

void start_application(char** argv)
{
    int option = -1;
    printf("> Starting application....\n");
    printf("Tasks: \n");
    printf("1. ASCII TO BIN and BINASCII conversions.\n");
    printf("2. Master Key ASN1 structure that handles big numbers.\n");
    printf("3. AES OFB personalized algorithm.\n");
    printf("4. Transmission of ASN1 data structure packets between some people.\n");
    printf("5. Personalized data encrypt/decrypt algorithm.\n");
    printf("> Introduce the number of task to test a specific functionality: ");
    scanf("%d", &option);
    if (option == 1)
        conversions();
    else if (option == 2)
        master_key_struct_usage();
    else if (option == 3)
        test_aes_ofb(argv[1]);
    else if (option == 4)
        test_communication();
    else if (option == 5)
        keystream_gen();
    else
        printf("> Invalid option introduced!");
    exit(EXIT_SUCCESS);
}


int main(int argc, char* argv[])
{   
    start_application(argv);


    return 0;
}