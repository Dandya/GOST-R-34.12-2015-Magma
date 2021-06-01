/*
Функция S_box производит нелинейное биективное преобразование.
Принимает на вход:
 uint32_t rightPart - 32-х битное беззнаковое число, являющиеся половиной шифруемого блока.
*/
static uint32_t S_box(uint32_t rightPart)
{
    int S [8][16]={
    {12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0,  3, 15, 1},
    {6,  8, 2, 3, 9, 10, 5, 12, 1, 14, 4,  7, 11, 13, 0, 15},
    {11, 3, 5, 8, 2, 15, 10, 13,14, 1, 7,  4, 12, 9,  6, 0},
    {12, 8, 2, 1, 13, 4, 15,  6, 7, 0, 10, 5, 3,  14, 9, 11},
    {7, 15, 5, 10, 8, 1, 6,  13, 0, 9, 3,  14, 11,4,  2, 12},
    {5, 13, 15, 6, 9, 2, 12, 10, 11,7, 8,   1, 4, 3, 14, 0},
    {8, 14,  2 ,5 ,6, 9, 1,  12, 15,4, 11,  0, 13,10, 3, 7},
    {1, 7,  14,13, 0, 5, 8,  3,  4, 15,10,  6, 9, 12, 11,2},
    };

    for(int i=0; i<=7; i++)
    {
       rightPart = rightPart & ~(0b1111<<(4*i)) | S[i][ (rightPart & (0b1111<<(4*i)) )>>(4*i) ]<<(4*i) ; //Замена элементов на соответствующие подстановки 
    }  
    return rightPart;   
}

/*
Циклическое смещение на 11 бит.
*/
#define cyclicShift(x) (x>>21 | x<<11)

/*
Функция oneFeistelIteration, производящая одну из итераций схемы Фейстеля с 1 по 31 итерацию. 
Принимает на вход:
uint32_t* leftAndRightPart - указатель на 32-х битное беззнаковое число шифруемого текста;
uint32_t key - итерационный ключ, размером в 32 бита.
*/
static void oneFeistelIteration(uint32_t* leftAndRightPart, uint32_t key)
{
    uint32_t result = S_box( leftAndRightPart[0] + key );
    result = leftAndRightPart[1] ^ cyclicShift(result);
    leftAndRightPart[1] = leftAndRightPart[0];
    leftAndRightPart[0] = result;
}

/*
Функция lastFeistelIteration, производящая последнюю итерацию схемы Фейстеля - 32-ю.
Принимает на вход:
uint32_t* leftAndRightPart - указатель на 32-х битное беззнаковое число шифруемого текста;
uint32_t key - итерационный ключ, размером в 32 бита.
*/
static void lastFeistelIteration(uint32_t* leftAndRightPart, uint32_t key)
{
    uint32_t result = S_box( leftAndRightPart[0] + key );
    result = cyclicShift(result);
    result = leftAndRightPart[1] ^ result;
    leftAndRightPart[1] = result;
}

/*
Функция createEncryptKeys выполняет алгоритм развертывания ключа в порядке нужном для зашифрования открытого текста.
Принимает на вход:
uint32_t* iterationKeys - указатель на массив, созданный для хранения итерационных ключей;
uint32_t* key - указатель на участок памяти, содержащий 256 бит секретного ключа.
*/
void createEncryptKeys(uint32_t* iterationKeys, uint32_t* key)
{
    int index;
    for(index = 0; index<24; index++)
    {
        iterationKeys[index] = key[7 - index%8];
    }
    for(index = 24; index<32; index++)
    {
        iterationKeys[index] = key[index%8];
    }
}

/*
Функция createDecryptKeys выполняет алгоритм развертывания ключа в порядке нужном для расшифрования открытого текста.
Принимает на вход:
uint32_t* iterationKeys - указатель на массив, созданный для хранения итерационных ключей;
uint32_t* key - указатель на участок памяти, содержащий 256 бит секретного ключа.
*/
void createDecryptKeys(uint32_t* iterationKeys, uint32_t* key)
{
    int index;
    for(index = 0; index<8; index++)
    {
        iterationKeys[index] = key[7 - index%8];
    }
    for(index = 8; index<32; index++)
    {
        iterationKeys[index] = key[index%8];
    }
}

/*
Функция getSizeInputFile реализует алгоритм для определения размера входной фаила.
Принимает на вход:
FILE* input - указатель на поток, являющейся открытым фаилом.
*/
uint64_t getSizeInputFile(FILE* input)
{
    uint64_t size;
    fseek(input, 0, SEEK_END);
    size = ftell(input);
    fseek(input, 0, SEEK_SET);
    return size;
}

/*
Функция schemeFeistel реализует алгоритм базового шифрования через схему Фейстеля. 
Принимает на вход:
uint64_t block - 64-х битное беззнаковое число, являющиеся шифруемым блоком;
uint32_t* ptrOnArrKeys - указатель на массив, содержащий итерационные ключи для выполнения блочного шифра.
*/
static uint64_t schemeFeistel(uint64_t block, uint32_t* ptrOnArrKeys)
{
    uint32_t* leftAndRightPart = (uint32_t*)&block; // 0 - rightPart, 1 - leftPart 
    for(int iteration = 0; iteration<31; iteration++)
    {
        oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[iteration]);
    }
    //end 1-31 iteration
    lastFeistelIteration(leftAndRightPart, ptrOnArrKeys[31]);
    return block;
}
/*********************************************************/
