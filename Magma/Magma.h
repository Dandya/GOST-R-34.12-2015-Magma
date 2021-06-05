#include <stdint.h>
#include <stdio.h>
#define SIZE_BLOCK 8
#define ALL_FILE 0
#define ECB 1
#define IMITO 6
#define PROC_ADD_NULLS_1 1
#define PROC_ADD_NULLS_2 2
#define PROC_ADD_NULLS_3 3
//IMITO
#define CREATE_KEY_1 1
#define CREATE_KEY_2 2
/*********************************************************/
static uint32_t S_box(uint32_t v_32);
static void oneFeistelIteration(uint32_t* leftAndRightPart, uint32_t key);
static void lastFeistelIteration(uint32_t* leftAndRightPart, uint32_t key);
void createEncryptKeys(uint32_t* iterationKeys, uint32_t* key);
void createDecryptKeys(uint32_t* iterationKeys, uint32_t* key);
uint64_t getSizeInputFile(FILE* input);
uint64_t readLastBlockInputFile(FILE* input, int modePadding, uint8_t countReadByte);
static uint64_t schemeFeistel(uint64_t block, uint32_t* ptrOnArrKeys);
uint64_t procPadding(uint8_t* data, int countAddByte, int mode);
uint8_t countBytesForWrite(uint8_t* blockInBytes);
int EncryptECB(FILE* inputFile, FILE* outputFile, uint64_t countBytesForCrypt, uint32_t* key , int modePadding);
int DecryptECB(FILE* inputFile, FILE* outputFile, uint64_t countBytesForCrypt, uint32_t* key , int modePadding,  uint8_t countByteInLastBlock);
static void readBlock(FILE* file, uint8_t* ptrOnBlock ,uint8_t countByteForRead);
//IMITO
uint64_t createHelpingKey(uint32_t* ptrOnArrKeys, int numberOfKeyToCreate);
uint64_t getMAC(FILE* input, uint64_t countBytesForCrypt_or_tmp, uint32_t* key, uint8_t sizeMAC);
/*********************************************************/
#include "./Basic_cipher.c"
#include "./ECB.c"
#include "./IMITO.c"
