/*
Функция EncryptECB реализует алгоритм зашифрования открытого текста.
FILE* inputFile - указатель на открытый фаил для чтения;
FILE* outputFile - указатель на открытый фаил для записи;
uint32_t* key - указатель на 256 битный ключ;
int modePadding - номер процедуры дополнения(по ГОСТ 34.13-2015).
*/
int EncryptECB(FILE* inputFile, FILE* outputFile, uint64_t countBytesForCrypt, uint32_t* key , int modePadding)
{
    //get count full blocks
    if(countBytesForCrypt == ALL_FILE)
    {
        countBytesForCrypt = getSizeInputFile(inputFile);
    }
    uint32_t countFullBlocks = countBytesForCrypt/SIZE_BLOCK;
    //create iteration keys
    uint32_t ptrOnArrKeys[32];
    createEncryptKeys(ptrOnArrKeys, key);
    //cipher full bloks
    uint64_t block;
    for(uint64_t iteration = 0; iteration<countFullBlocks; iteration++)
    {
        readBlock(inputFile, (uint8_t*)&block, SIZE_BLOCK);
        block = schemeFeistel(block, ptrOnArrKeys);
        fwrite(&block, SIZE_BLOCK, 1, outputFile);
    }
    //cipher last block
    if(countBytesForCrypt%SIZE_BLOCK != 0) // countBytesForCrypt%8 - count bytes in last block
    {
        //block = readLastBlockInputFile(inputFile, modePadding, countBytesForCrypt%8);
        readBlock(inputFile, (uint8_t*)&block, countBytesForCrypt%SIZE_BLOCK);
        procPadding((uint8_t*)&block, SIZE_BLOCK - countBytesForCrypt%SIZE_BLOCK, modePadding);
    }
    else if(modePadding == PROC_ADD_NULLS_2)
    {
        block = 0x0000000000000001;
    }
    else
    {
        return 0;
    }
    block = schemeFeistel(block, ptrOnArrKeys);
    fwrite(&block, 8, 1, outputFile);
    return 0;
}

/*
Функция DecryptECB реализует алгоритм расшифрования открытого текста.
FILE* inputFile - указатель на открытый фаил для чтения;
FILE* outputFile - указатель на открытый фаил для записи;
uint32_t* key - указатель на 256 битный ключ;
int modePadding - номер процедуры дополнения(по ГОСТ 34.13-2015);
uint8_t countByteInLastBlock - 8-ми битное беззнаковое число, являющееся количеством байт в последнем блоке при расшифровании(нужно для первой процедуры дополнения).
*/
int DecryptECB(FILE* inputFile, FILE* outputFile, uint64_t countBytesForCrypt, uint32_t* key , int modePadding,  uint8_t countByteInLastBlock)
{
    //open files
    /*FILE* inputFile = fopen(nameInputFile, "rb");
    FILE* outputFile = fopen(nameOutputFile, "wb");
    if(inputFile == NULL || outputFile == NULL)
    {
        printf("error open files\n");
        return 2;
    }*/
    
    //get count full blocks
    if(countBytesForCrypt == ALL_FILE)
    {
        countBytesForCrypt = getSizeInputFile(inputFile);
    }
    uint32_t countFullBlocks = countBytesForCrypt/SIZE_BLOCK - 1;
    //create iteration keys
    uint32_t ptrOnArrKeys[32];
    createDecryptKeys(ptrOnArrKeys, key);    
    //cipher full bloks
    uint64_t block;
    for(uint64_t iteration = 0; iteration<countFullBlocks; iteration++)
    {
        readBlock(inputFile, (uint8_t*)&block, SIZE_BLOCK);
        block = schemeFeistel(block, ptrOnArrKeys);
        fwrite(&block, SIZE_BLOCK, 1, outputFile);
    }
    //cipher last block
    readBlock(inputFile, (uint8_t*)&block, SIZE_BLOCK);
    block = schemeFeistel(block, ptrOnArrKeys);
    if(modePadding == PROC_ADD_NULLS_2)
    {
        fwrite(&block, countBytesForWrite((uint8_t*)&block), 1, outputFile);
    }
    else 
    {
        fwrite(&block, countByteInLastBlock, 1, outputFile);   
    }
    return 0;
}

/*
Функция procPadding - реализует процедуры дополнения, описанные в ГОСТ Р 34.13-2015, кроме условий полного блока.
Принимает на вход:
uint8_t* data - указатель на ячейку памяти с читаемым последним блоком;
int countAddByte - целое число, обозначающее количество байт, которые нужно добавить в блок;
int mode - режим добавления.
*/
uint64_t procPadding(uint8_t* data, int countAddByte, int mode)
{
    if(mode == PROC_ADD_NULLS_1)
    {
        for(int index = SIZE_BLOCK - countAddByte; index<SIZE_BLOCK; index++)
        {
            data[index] = 0;
        }
        return 0;
    }
    else
    {
        data[SIZE_BLOCK - countAddByte] = 1;
        for(int index = SIZE_BLOCK - (countAddByte - 1); index<SIZE_BLOCK; index++)
        {
            data[index] = 0;
        }
        return 0;
    }
}

/*
Функция countBytesForWrite обеспечивает правильное расшифрование закрытого текста, а имеено возвращает количество байт последнего блока, которое нужно записать в фаил, чтобы получить открытый текст, зашифрованный при помощи второй процедуры дополнения.
Принимает на вход:
uint8_t* blockInBytes -указатель на ячейку памяти с последним блоком закрытого текста.
*/
uint8_t countBytesForWrite(uint8_t* blockInBytes)
{
    int indexByte = 7;
    while(blockInBytes[indexByte] != 1)
    {
        indexByte--;
    }
    return indexByte; // count bytes in open text
}

/*
Функция readBlock обеспечивает чтение блока из фаила.
Принимает на вход:
FILE* file - файловый дескриптор; 
uint8_t* ptrOnBlock - указатель на блок;
uint8_t countByteForRead - количество считываемых байт.
*/
static void readBlock(FILE* file, uint8_t* ptrOnBlock ,uint8_t countByteForRead)
{
    while(countByteForRead--)
    {
        *ptrOnBlock = fgetc(file);
        ptrOnBlock++;
    }
}
/*********************************************************/
