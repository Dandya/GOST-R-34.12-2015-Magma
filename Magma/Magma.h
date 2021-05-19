#include <stdint.h>
#include <stdio.h>
#define SIZE_BLOCK 8
#define ECB 1
#define IMITO 6
#define PROC_ADD_NULLS_1 1
#define PROC_ADD_NULLS_2 2
#define PROC_ADD_NULLS_3 3
//IMITO
#define CREATE_KEY_1 1
#define CREATE_KEY_2 2
/*********************************************************/
uint32_t S_box(uint32_t v_32);
void oneFeistelIteration(uint32_t* leftAndRightPart, uint32_t key);
void lastFeistelIteration(uint32_t* leftAndRightPart, uint32_t key);
void createEncryptKeys(uint32_t* iterationKeys, uint32_t* key);
void createDecryptKeys(uint32_t* iterationKeys, uint32_t* key);
uint64_t getSizeInputFile(FILE* input);
uint64_t readLastBlockInputFile(FILE* input, int modePadding, uint8_t countReadByte);
uint64_t schemeFeistel(uint64_t block, uint32_t* ptrOnArrKeys);
uint64_t procPadding(uint8_t* data, int countAddByte, int mode);
uint8_t countBytesForWrite(uint8_t* blockInBytes);
int EncryptECB(char* nameInputFile, char* nameOutputFile, uint32_t* key , int modePadding);
int DecryptECB(char* nameInputFile, char* nameOutputFile, uint32_t* key , int modePadding,  uint8_t countByteInLastBlock);
//IMITO
uint64_t createHelpingKey(uint32_t* ptrOnArrKeys, int numberOfKeyToCreate);
uint64_t getMAC(char* nameInputFile, uint32_t* key , uint8_t sizeMAC);
/*********************************************************/
#include "./Basic_cipher.c"
#include "./ECB.c"
#include "./IMITO.c"
