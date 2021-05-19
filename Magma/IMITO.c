/*
Функция createHelpingKey реализует алгоритм создания вспомогательных ключей  для блока размером 64 бита режима выработки имитовставки.
uint32_t* ptrOnArrKeys - указатель на массив с итерационными ключами для базового шифра;
int numberOfKeyToCreate - номер вспомогательного ключа, который выбирается в зависимости от размера последнего блока.
*/
uint64_t createHelpingKey(uint32_t* ptrOnArrKeys, int numberOfKeyToCreate)
{
    uint64_t key = schemeFeistel(0, ptrOnArrKeys);
    //create First  key 
    if(!((key & (0b1<<63))>>63))
    {
        key = key<<1;
    }
    else
    {
        key = (key<<1)^0b11011;
    }
    if(numberOfKeyToCreate == CREATE_KEY_1)
    {
        return key;
    }
    //create Second key
    if(!(key & (0b1<<63)))
    {
        key = key<<1;
    }
    else
    {
        key = (key<<1)^0b11011;
    }
    return key;
}
/*
Функция getMAC реализует режим выработки имитовставки.
char* nameInputFile - указатель на массив символов, содержащий имя фаила с открытым текстом;
uint32_t* key - указатель на 256 битный ключ;
uint8_t sizeMAC - 8-ми битовое число, являющееся размером имитовставки в битах.
*/
uint64_t getMAC(char* nameInputFile, uint32_t* key , uint8_t sizeMAC)
{
    //open input file
    FILE* input = fopen(nameInputFile, "r");
    if(input == NULL)
    {
        printf("error open files\n");
        return -1;
    }
    //get count full blocks
    uint64_t tmp = getSizeInputFile(input);
    uint8_t residue = tmp%SIZE_BLOCK;
    uint32_t countFullBlocks = residue == 0 ? tmp/SIZE_BLOCK - 1 : tmp/SIZE_BLOCK;
    //create iterationKeys
    uint32_t ptrOnArrKeys[32];
    createEncryptKeys(ptrOnArrKeys, key);
    //create MAC
    uint64_t block; 
    tmp = 0;
    for(int iteration = 0; iteration<countFullBlocks; iteration++)
    {
        fread(&block, SIZE_BLOCK, 1, input);
        block ^= tmp;
        block = schemeFeistel(block, ptrOnArrKeys);
        tmp = block;
    }
    //read last block and create helping key
    uint64_t helpingKey;
    if(residue != 0)
    {
        fread(&block, residue, 1, input);
        procPadding((uint8_t*)&block, SIZE_BLOCK - residue, PROC_ADD_NULLS_3);
        helpingKey = createHelpingKey(ptrOnArrKeys,CREATE_KEY_2);
    }
    else
    {
        fread(&block, SIZE_BLOCK, 1, input);
        helpingKey = createHelpingKey(ptrOnArrKeys, CREATE_KEY_1);
    }
    fclose(input);
    //create need key
    block ^= tmp^helpingKey;
    block = schemeFeistel(block, ptrOnArrKeys);
    return block>>(64 - sizeMAC);
}
