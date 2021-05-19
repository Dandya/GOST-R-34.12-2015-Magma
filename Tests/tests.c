#include "../Magma/Magma.h"
#include "/home/alex/gtest/include/gtest/gtest.h"
/*********************************************************/
uint32_t gFunc(uint32_t key, uint32_t halfBlock)
{
    uint32_t result = S_box( halfBlock + key );
    return (result & 0b11111111111<<21)>>21 | result<<11;
}
/*********************************************************/
TEST(Basic_Cipher, S_Box)
{
    EXPECT_EQ(S_box(0xFDB97531), 0x2A196F34);
    EXPECT_EQ(S_box(0x2A196F34), 0xEBD9F03A);
    EXPECT_EQ(S_box(0xEBD9F03A), 0xB039BB3D);
    EXPECT_EQ(S_box(0xB039BB3D), 0x68695433);
}
/*********************************************************/
TEST(Basic_Cipher, gFunction)
//проверка g[k] - отображения. В данном случае - части кода.
{
    EXPECT_EQ(gFunc(0x87654321, 0xFEDCBA98), 0xFDCBC20C);
    EXPECT_EQ(gFunc(0xFDCBC20C, 0x87654321), 0x7E791A4B);
    EXPECT_EQ(gFunc(0x7E791A4B, 0xFDCBC20C), 0xC76549EC);
    EXPECT_EQ(gFunc(0xC76549EC, 0x7E791A4B), 0x9791C849);
}
/*********************************************************/
TEST(Basic_Cipher, CreateEncryptKeys)
{
    uint32_t key[8]={0xFCFDFEFF, 0xF8F9FAFB, 0xF4F5F6F7, 0xF0F1F2F3, 0x33221100, 0x77665544, 0xBBAA9988, 0xFFEEDDCC};
    uint32_t iterationKeys[32];
    createEncryptKeys(iterationKeys, key);
    for(int index = 0; index<24; index++)
    {
        EXPECT_EQ(iterationKeys[index], key[7 - index%8]);   
    }
    for(int index = 24; index<32; index++)
    {
        EXPECT_EQ(iterationKeys[index], key[index%8]);   
    }
}
/*********************************************************/
TEST(Basic_Cipher, CreateDecryptKeys)
{
    uint32_t key[8]={0xFCFDFEFF, 0xF8F9FAFB, 0xF4F5F6F7, 0xF0F1F2F3, 0x33221100, 0x77665544, 0xBBAA9988, 0xFFEEDDCC};
    uint32_t iterationKeys[32];
    createDecryptKeys(iterationKeys, key);
    for(int index = 0; index<8; index++)
    {
        EXPECT_EQ(iterationKeys[index], key[7 - index%8]);   
    }
    for(int index = 8; index<32; index++)
    {
        EXPECT_EQ(iterationKeys[index], key[index%8]);   
    }
}
/*********************************************************/
TEST(Basic_Cipher, SchemeFeistelEncryption)
{
    uint32_t leftAndRightPart[2] = {0x76543210, 0xFEDCBA98}; // 0 - rightPart, 1 - leftPart 
    EXPECT_EQ(leftAndRightPart[0],0x76543210 );
    EXPECT_EQ(leftAndRightPart[1],0xFEDCBA98);
    uint32_t key[8]={0xFCFDFEFF, 0xF8F9FAFB, 0xF4F5F6F7, 0xF0F1F2F3, 0x33221100, 0x77665544, 0xBBAA9988, 0xFFEEDDCC};
    uint32_t ptrOnArrKeys[32];
    int iteration = 0;
    createEncryptKeys(ptrOnArrKeys, key);
    //1    
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0x28da3b14);
    ASSERT_EQ(leftAndRightPart[1], 0x76543210);
    //2
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0xb14337a5);
    ASSERT_EQ(leftAndRightPart[1], 0x28da3b14);
    //3
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0x633a7c68);
    ASSERT_EQ(leftAndRightPart[1], 0xb14337a5);
    //4
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0xea89c02c);
    ASSERT_EQ(leftAndRightPart[1], 0x633a7c68);
    //5
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0x11fe726d);
    ASSERT_EQ(leftAndRightPart[1], 0xea89c02c);
    //6
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0xad0310a4);
    ASSERT_EQ(leftAndRightPart[1], 0x11fe726d);
    //7
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0x37d97f25);
    ASSERT_EQ(leftAndRightPart[1], 0xad0310a4);
    //8    
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0x46324615);
    ASSERT_EQ(leftAndRightPart[1], 0x37d97f25);
    //9     
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0xce995f2a);
    ASSERT_EQ(leftAndRightPart[1], 0x46324615);
    //10     
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0x93c1f449);
    ASSERT_EQ(leftAndRightPart[1], 0xce995f2a);
    //11 
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0x4811c7ad);
    ASSERT_EQ(leftAndRightPart[1], 0x93c1f449);
    //12    
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0xc4b3edca);
    ASSERT_EQ(leftAndRightPart[1], 0x4811c7ad);
    //13
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0x44ca5ce1);
    ASSERT_EQ(leftAndRightPart[1], 0xc4b3edca);
    //14    
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0xfef51b68);
    ASSERT_EQ(leftAndRightPart[1], 0x44ca5ce1);
    //15    
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0x2098cd86);
    ASSERT_EQ(leftAndRightPart[1], 0xfef51b68);
    //16
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0x4f15b0bb);
    ASSERT_EQ(leftAndRightPart[1], 0x2098cd86);
    //17    
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0xe32805bc);
    ASSERT_EQ(leftAndRightPart[1], 0x4f15b0bb);
    //18    
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0xe7116722);
    ASSERT_EQ(leftAndRightPart[1], 0xe32805bc);
    //19    
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0x89cadf21);
    ASSERT_EQ(leftAndRightPart[1], 0xe7116722);
    //20        
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0xbac8444d);
    ASSERT_EQ(leftAndRightPart[1], 0x89cadf21);
    //21    
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0x11263a21);
    ASSERT_EQ(leftAndRightPart[1], 0xbac8444d);
    //22    
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0x625434c3);
    ASSERT_EQ(leftAndRightPart[1], 0x11263a21);
    //23    
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0x8025c0a5);
    ASSERT_EQ(leftAndRightPart[1], 0x625434c3);
    //24    
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0xb0d66514);
    ASSERT_EQ(leftAndRightPart[1], 0x8025c0a5);
    //25    
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0x47b1d5f4);
    ASSERT_EQ(leftAndRightPart[1], 0xb0d66514);
    //26    
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0xc78e6d50);
    ASSERT_EQ(leftAndRightPart[1], 0x47b1d5f4);
    //27    
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0x80251e99);
    ASSERT_EQ(leftAndRightPart[1], 0xc78e6d50);
    //28    
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0x2b96eca6);
    ASSERT_EQ(leftAndRightPart[1], 0x80251e99);
    //29    
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0x05ef4401);
    ASSERT_EQ(leftAndRightPart[1], 0x2b96eca6);
    //30    
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0x239a4577);
    ASSERT_EQ(leftAndRightPart[1], 0x05ef4401);
    //31
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0xc2d8ca3d);
    ASSERT_EQ(leftAndRightPart[1], 0x239a4577);
    //end 1-31 iteration
    lastFeistelIteration(leftAndRightPart, ptrOnArrKeys[31]);
    ASSERT_EQ(*((uint64_t*)leftAndRightPart), 0x4ee901e5c2d8ca3d);
}
/*********************************************************/
TEST(Basic_Cipher, SchemeFeistelDecryption)
{
    uint32_t leftAndRightPart[2] = {0xc2d8ca3d, 0x4ee901e5}; // 0 - rightPart, 1 - leftPart 
    uint32_t key[8]={0xFCFDFEFF, 0xF8F9FAFB, 0xF4F5F6F7, 0xF0F1F2F3, 0x33221100, 0x77665544, 0xBBAA9988, 0xFFEEDDCC};
    uint32_t ptrOnArrKeys[32];
    int iteration = 0;
    createDecryptKeys(ptrOnArrKeys, key);
    //32 - key    
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0x239a4577);
    ASSERT_EQ(leftAndRightPart[1], 0xc2d8ca3d);
    //31
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0x05ef4401);
    ASSERT_EQ(leftAndRightPart[1], 0x239a4577);
    //30
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0x2b96eca6);
    ASSERT_EQ(leftAndRightPart[1], 0x05ef4401);
    //29
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0x80251e99);
    ASSERT_EQ(leftAndRightPart[1], 0x2b96eca6);
    //28
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0xc78e6d50);
    ASSERT_EQ(leftAndRightPart[1], 0x80251e99);
    //27
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0x47b1d5f4);
    ASSERT_EQ(leftAndRightPart[1], 0xc78e6d50);
    //26
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0xb0d66514);
    ASSERT_EQ(leftAndRightPart[1], 0x47b1d5f4);
    //25    
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0x8025c0a5);
    ASSERT_EQ(leftAndRightPart[1], 0xb0d66514);
    //24     
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0x625434c3);
    ASSERT_EQ(leftAndRightPart[1], 0x8025c0a5);
    //23     
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0x11263a21);
    ASSERT_EQ(leftAndRightPart[1], 0x625434c3);
    //22 
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0xbac8444d);
    ASSERT_EQ(leftAndRightPart[1], 0x11263a21);
    //21    
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0x89cadf21);
    ASSERT_EQ(leftAndRightPart[1], 0xbac8444d);
    //20
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0xe7116722);
    ASSERT_EQ(leftAndRightPart[1], 0x89cadf21);
    //19    
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0xe32805bc);
    ASSERT_EQ(leftAndRightPart[1], 0xe7116722);
    //18    
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0x4f15b0bb);
    ASSERT_EQ(leftAndRightPart[1], 0xe32805bc);
    //17
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0x2098cd86);
    ASSERT_EQ(leftAndRightPart[1], 0x4f15b0bb);
    //16    
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0xfef51b68);
    ASSERT_EQ(leftAndRightPart[1], 0x2098cd86);
    //15    
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0x44ca5ce1);
    ASSERT_EQ(leftAndRightPart[1], 0xfef51b68);
    //14    
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0xc4b3edca);
    ASSERT_EQ(leftAndRightPart[1], 0x44ca5ce1);
    //13        
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0x4811c7ad);
    ASSERT_EQ(leftAndRightPart[1], 0xc4b3edca);
    //12    
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0x93c1f449);
    ASSERT_EQ(leftAndRightPart[1], 0x4811c7ad);
    //11    
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0xce995f2a);
    ASSERT_EQ(leftAndRightPart[1], 0x93c1f449);
    //10    
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0x46324615);
    ASSERT_EQ(leftAndRightPart[1], 0xce995f2a);
    //9    
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0x37d97f25);
    ASSERT_EQ(leftAndRightPart[1], 0x46324615);
    //8    
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0xad0310a4);
    ASSERT_EQ(leftAndRightPart[1], 0x37d97f25);
    //7    
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0x11fe726d);
    ASSERT_EQ(leftAndRightPart[1], 0xad0310a4);
    //6    
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0xea89c02c);
    ASSERT_EQ(leftAndRightPart[1], 0x11fe726d);
    //5    
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0x633a7c68);
    ASSERT_EQ(leftAndRightPart[1], 0xea89c02c);
    //4    
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0xb14337a5);
    ASSERT_EQ(leftAndRightPart[1], 0x633a7c68);
    //3    
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0x28da3b14);
    ASSERT_EQ(leftAndRightPart[1], 0xb14337a5);
    //2
    oneFeistelIteration(leftAndRightPart, ptrOnArrKeys[++iteration]);
    ASSERT_EQ(leftAndRightPart[0], 0x76543210);
    ASSERT_EQ(leftAndRightPart[1], 0x28da3b14);
    //1
    lastFeistelIteration(leftAndRightPart, ptrOnArrKeys[31]);
    ASSERT_EQ(*((uint64_t*)leftAndRightPart), 0xfedcba9876543210);
}
/*********************************************************/
TEST(Basic_Cipher, SchemeFeistelEncryption2)
{
    uint64_t block = 0xFEDCBA9876543210; // 0 - rightPart, 1 - leftPart 
    uint32_t key[8]={0xFCFDFEFF, 0xF8F9FAFB, 0xF4F5F6F7, 0xF0F1F2F3, 0x33221100, 0x77665544, 0xBBAA9988, 0xFFEEDDCC};
    uint32_t ptrOnArrKeys[32];
    int iteration = 0;
    createEncryptKeys(ptrOnArrKeys, key);
    EXPECT_EQ(schemeFeistel(block, ptrOnArrKeys), 0x4ee901e5c2d8ca3d);
}
/*********************************************************/
TEST(Basic_Cipher, SchemeFeistelDecryption2)
{
    uint64_t block = 0x4ee901e5c2d8ca3d; // 0 - rightPart, 1 - leftPart 
    uint32_t key[8]={0xFCFDFEFF, 0xF8F9FAFB, 0xF4F5F6F7, 0xF0F1F2F3, 0x33221100, 0x77665544, 0xBBAA9988, 0xFFEEDDCC};
    uint32_t ptrOnArrKeys[32];
    int iteration = 0;
    createDecryptKeys(ptrOnArrKeys, key);
    EXPECT_EQ(schemeFeistel(block, ptrOnArrKeys),  0xFEDCBA9876543210);
}
/*********************************************************/
TEST(ecb, ProcPaddingNulls)
{
    uint64_t block = 0x1234567890; //5 - bytes
    procPadding((uint8_t*)&block, 3, PROC_ADD_NULLS_1);
    EXPECT_EQ(block, 0x0000001234567890);
    procPadding((uint8_t*)&block, 3, PROC_ADD_NULLS_2);
    EXPECT_EQ(block, 0x0000011234567890);
    procPadding((uint8_t*)&block, 8, PROC_ADD_NULLS_2);
    EXPECT_EQ(block, 0x0000000000000001);
}
/*********************************************************/
TEST(ecb, CountBytesForWrite)
{
    uint64_t block = 0x0000011234567890; //5 - bytes
    EXPECT_EQ(countBytesForWrite((uint8_t*)&block), 5);
    block = 0x0000000000000001; //5 - bytes
    EXPECT_EQ(countBytesForWrite((uint8_t*)&block), 0);
    block = 0x0000011234567890; //5 - bytes
    EXPECT_EQ(countBytesForWrite((uint8_t*)&block), 5);
}
/*********************************************************/
TEST(ecb, CipherECB_proc_added_nulls_1_full_block)
{

    char nameInputFile[] = "OpenText.txt";
    char nameOutputFile[] = "CipherText.txt";
    //create open text
    uint64_t block = 0xfedcba9876543210;
    FILE* openText = fopen("OpenText.txt", "w");
    if(openText == NULL)
    {
        printf("what!!! Where file? (0_0)\n");
    }
    for(int iteration = 1; iteration <= 4; iteration++)
    {
        if(fwrite(&block, 8, 1, openText) != 1)
        {
            printf("what?!\n");
        }
    }
    fclose(openText);
    //encryption
    uint32_t key[8]={0xFCFDFEFF, 0xF8F9FAFB, 0xF4F5F6F7, 0xF0F1F2F3, 0x33221100, 0x77665544, 0xBBAA9988, 0xFFEEDDCC};
    EXPECT_EQ(EncryptECB(nameInputFile, nameOutputFile, key, PROC_ADD_NULLS_1), 0);
    //check cipher text
    FILE* cipherText = fopen("CipherText.txt", "r");
    for(int iteration = 1; iteration <= 4; iteration++)
    {
        fread(&block, 8, 1, cipherText);
        EXPECT_EQ(block, 0x4ee901e5c2d8ca3d);
    }
    EXPECT_EQ(fgetc(cipherText), EOF);
    fclose(cipherText);
    //decryption
    EXPECT_EQ(DecryptECB(nameOutputFile, nameInputFile, key, PROC_ADD_NULLS_1, 8), 0);
    //check open text
    openText = fopen("OpenText.txt", "r");
    for(int iteration = 1; iteration <= 4; iteration++)
    {
        fread(&block, 8, 1, openText);
        EXPECT_EQ(block, 0xfedcba9876543210);
    }
    EXPECT_EQ(fgetc(openText), EOF);
    fclose(openText);
}
/*********************************************************/
TEST(ecb, CipherECB_proc_added_nulls_1_not_full_block)
{

    char nameInputFile[] = "OpenText.txt";
    char nameOutputFile[] = "CipherText.txt";
    //create open text
    uint64_t block = 0xfedcba9876543210;
    FILE* openText = fopen("OpenText.txt", "w+");
    if(openText == NULL)
    {
        printf("what!!! Where file? (0_0)\n");
    }
    for(int iteration = 1; iteration <= 4; iteration++)
    {
        if(fwrite(&block, 8, 1, openText) != 1)
        {
            printf("what?!\n");
        }
    }
    block = 0x6543210;
    if(fwrite(&block, 4, 1, openText) != 1)
        {
            printf("what?!\n");
        }
    fclose(openText);
    //encryption
    uint32_t key[8]={0xFCFDFEFF, 0xF8F9FAFB, 0xF4F5F6F7, 0xF0F1F2F3, 0x33221100, 0x77665544, 0xBBAA9988, 0xFFEEDDCC};
    EXPECT_EQ(EncryptECB(nameInputFile, nameOutputFile, key, PROC_ADD_NULLS_1), 0);
    //check cipher text
    FILE* cipherText = fopen("CipherText.txt", "r");
    for(int iteration = 1; iteration <= 4; iteration++)
    {
        fread(&block, 8, 1, cipherText);
        EXPECT_EQ(block, 0x4ee901e5c2d8ca3d);
    }
    EXPECT_EQ(feof(cipherText), 0);
    fclose(cipherText);
    //decryption
    EXPECT_EQ(DecryptECB(nameOutputFile, nameInputFile, key, PROC_ADD_NULLS_1, 4), 0);
    //check open text
    openText = fopen("OpenText.txt", "r");
    for(int iteration = 1; iteration <= 4; iteration++)
    {
        fread(&block, 8, 1, openText);
        EXPECT_EQ(block, 0xfedcba9876543210);
    }
    block = 0;
    fread(&block, 4, 1, openText);
    EXPECT_EQ(block,  0x6543210);
    EXPECT_EQ(fgetc(openText), EOF);
    fclose(openText);
}
/*********************************************************/
TEST(ecb, CipherECB_proc_added_nulls_2_not_full_block)
{

    char nameInputFile[] = "OpenText.txt";
    char nameOutputFile[] = "CipherText.txt";
    //create open text
    uint64_t block = 0xfedcba9876543210;
    FILE* openText = fopen("OpenText.txt", "w+");
    if(openText == NULL)
    {
        printf("what!!! Where file? (0_0)\n");
    }
    for(int iteration = 1; iteration <= 4; iteration++)
    {
        if(fwrite(&block, 8, 1, openText) != 1)
        {
            printf("what?!\n");
        }
    }
    block = 0x6543210;
    if(fwrite(&block, 4, 1, openText) != 1)
        {
            printf("what?!\n");
        }
    fclose(openText);
    //encryption
    uint32_t key[8]={0xFCFDFEFF, 0xF8F9FAFB, 0xF4F5F6F7, 0xF0F1F2F3, 0x33221100, 0x77665544, 0xBBAA9988, 0xFFEEDDCC};
    EXPECT_EQ(EncryptECB(nameInputFile, nameOutputFile, key, PROC_ADD_NULLS_2), 0);
    //check cipher text
    FILE* cipherText = fopen("CipherText.txt", "r");
    for(int iteration = 1; iteration <= 4; iteration++)
    {
        fread(&block, 8, 1, cipherText);
        EXPECT_EQ(block, 0x4ee901e5c2d8ca3d);
    }
    EXPECT_EQ(feof(cipherText), 0);
    fclose(cipherText);
    //decryption
    EXPECT_EQ(DecryptECB(nameOutputFile, nameInputFile, key, PROC_ADD_NULLS_2, 0), 0);
    //check open text
    openText = fopen("OpenText.txt", "r");
    for(int iteration = 1; iteration <= 4; iteration++)
    {
        fread(&block, 8, 1, openText);
        EXPECT_EQ(block, 0xfedcba9876543210);
    }
    block = 0;
    fread(&block, 4, 1, openText);
    EXPECT_EQ(block,  0x6543210);
    fclose(openText);
}
/*********************************************************/
TEST(ecb, CipherECB_proc_added_nulls_2_full_block)
{

    char nameInputFile[] = "OpenText.txt";
    char nameOutputFile[] = "CipherText.txt";
     uint32_t key[8]={0xFCFDFEFF, 0xF8F9FAFB, 0xF4F5F6F7, 0xF0F1F2F3, 0x33221100, 0x77665544, 0xBBAA9988, 0xFFEEDDCC};
    //create open text
    uint64_t block = 0xfedcba9876543210;
    FILE* openText = fopen("OpenText.txt", "w");
    if(openText == NULL)
    {
        printf("what!!! Where file? (0_0)\n");
    }
    for(int iteration = 1; iteration <= 4; iteration++)
    {
        if(fwrite(&block, 8, 1, openText) != 1)
        {
            printf("what?!\n");
        }
    }
    fclose(openText);
    //encryption
    EXPECT_EQ(EncryptECB(nameInputFile, nameOutputFile, key, PROC_ADD_NULLS_2), 0);
    //check cipher text
    FILE* cipherText = fopen("CipherText.txt", "r");
    for(int iteration = 1; iteration <= 4; iteration++)
    {
        fread(&block, 8, 1, cipherText);
        EXPECT_EQ(block, 0x4ee901e5c2d8ca3d);
    }
    EXPECT_EQ(feof(cipherText), 0);
    fclose(cipherText);
    //decryption
    EXPECT_EQ(DecryptECB(nameOutputFile, nameInputFile, key, PROC_ADD_NULLS_2, 0), 0);
    //check open text
    openText = fopen("OpenText.txt", "r");
    for(int iteration = 1; iteration <= 4; iteration++)
    {
        fread(&block, 8, 1, openText);
        EXPECT_EQ(block, 0xfedcba9876543210);
    }
    EXPECT_EQ(fgetc(openText), EOF);
    fclose(openText);
}
/*********************************************************/
TEST(ecb, SPEED_ENCRYPTION_MODE)
{
    char nameInputFile[] = "OpenText.txt";
    char nameOutputFile[] = "CipherText.txt";
    uint32_t key[8]={0xFCFDFEFF, 0xF8F9FAFB, 0xF4F5F6F7, 0xF0F1F2F3, 0x33221100, 0x77665544, 0xBBAA9988, 0xFFEEDDCC};
    EncryptECB(nameInputFile, nameOutputFile, key, PROC_ADD_NULLS_2);
}
/*********************************************************/
TEST(ecb, SPEED_DECRYPTION_MODE)
{
    char nameInputFile[] = "OpenText.txt";
    char nameOutputFile[] = "CipherText.txt";
    uint32_t key[8]={0xFCFDFEFF, 0xF8F9FAFB, 0xF4F5F6F7, 0xF0F1F2F3, 0x33221100, 0x77665544, 0xBBAA9988, 0xFFEEDDCC};
    DecryptECB(nameOutputFile, nameInputFile, key, PROC_ADD_NULLS_2, 0);
}
/*********************************************************/
TEST(ecb, SmallTest1)
{
    char nameInputFile[] = "OpenText.txt";
    char nameOutputFile[] = "CipherText.txt";
    //create open text
    uint64_t block = 0x92def06b3c130a59;
    FILE* openText = fopen("OpenText.txt", "w");
    if(openText == NULL)
    {
        printf("what!!! Where file? (0_0)\n");
    }
    if(fwrite(&block, 8, 1, openText) != 1)
    {
        printf("what?!\n");
    }
    fclose(openText);
    uint32_t key[8]={0xFCFDFEFF, 0xF8F9FAFB, 0xF4F5F6F7, 0xF0F1F2F3, 0x33221100, 0x77665544, 0xBBAA9988, 0xFFEEDDCC};
    //encryption
    EXPECT_EQ(EncryptECB(nameInputFile, nameOutputFile, key, PROC_ADD_NULLS_2), 0);
    //check cipher text
    FILE* cipherText = fopen("CipherText.txt", "r");
    fread(&block, 8, 1, cipherText);
    EXPECT_EQ(block, 0x2b073f0494f372a0);
    EXPECT_EQ(feof(cipherText), 0);
    fclose(cipherText);
    //decryption
    EXPECT_EQ(DecryptECB(nameOutputFile, nameInputFile, key, PROC_ADD_NULLS_2, 0), 0);
    //check open text
    openText = fopen("OpenText.txt", "r");
    fread(&block, 8, 1, openText);
    EXPECT_EQ(block, 0x92def06b3c130a59);
    EXPECT_EQ(fgetc(openText), EOF);
    fclose(openText);
}
/*********************************************************/
TEST(ecb, SmallTest2)
{
    char nameInputFile[] = "OpenText.txt";
    char nameOutputFile[] = "CipherText.txt";
    //create open text
    uint64_t block = 0xdb54c704f8189d20;
    FILE* openText = fopen("OpenText.txt", "w");
    if(openText == NULL)
    {
        printf("what!!! Where file? (0_0)\n");
    }
    if(fwrite(&block, 8, 1, openText) != 1)
    {
        printf("what?!\n");
    }
    fclose(openText);
    uint32_t key[8]={0xFCFDFEFF, 0xF8F9FAFB, 0xF4F5F6F7, 0xF0F1F2F3, 0x33221100, 0x77665544, 0xBBAA9988, 0xFFEEDDCC};
    //encryption
    EXPECT_EQ(EncryptECB(nameInputFile, nameOutputFile, key, PROC_ADD_NULLS_2), 0);
    //check cipher text
    FILE* cipherText = fopen("CipherText.txt", "r");
    fread(&block, 8, 1, cipherText);
    EXPECT_EQ(block, 0xde70e715d3556e48);
    EXPECT_EQ(feof(cipherText), 0);
    fclose(cipherText);
    //decryption
    EXPECT_EQ(DecryptECB(nameOutputFile, nameInputFile, key, PROC_ADD_NULLS_2, 0), 0);
    //check open text
    openText = fopen("OpenText.txt", "r");
    fread(&block, 8, 1, openText);
    EXPECT_EQ(block, 0xdb54c704f8189d20);
    EXPECT_EQ(fgetc(openText), EOF);
    fclose(openText);
}
/*********************************************************/
TEST(ecb, SmallTest3)
{
    char nameInputFile[] = "OpenText.txt";
    char nameOutputFile[] = "CipherText.txt";
    //create open text
    uint64_t block = 0x4a98fb2e67a8024c;
    FILE* openText = fopen("OpenText.txt", "w");
    if(openText == NULL)
    {
        printf("what!!! Where file? (0_0)\n");
    }
    if(fwrite(&block, 8, 1, openText) != 1)
    {
        printf("what?!\n");
    }
    fclose(openText);
    uint32_t key[8]={0xFCFDFEFF, 0xF8F9FAFB, 0xF4F5F6F7, 0xF0F1F2F3, 0x33221100, 0x77665544, 0xBBAA9988, 0xFFEEDDCC};
    //encryption
    EXPECT_EQ(EncryptECB(nameInputFile, nameOutputFile, key, PROC_ADD_NULLS_2), 0);
    //check cipher text
    FILE* cipherText = fopen("CipherText.txt", "r");
    fread(&block, 8, 1, cipherText);
    EXPECT_EQ(block, 0x11d8d9e9eacfbc1e);
    EXPECT_EQ(feof(cipherText), 0);
    fclose(cipherText);
    //decryption
    EXPECT_EQ(DecryptECB(nameOutputFile, nameInputFile, key, PROC_ADD_NULLS_2, 0), 0);
    //check open text
    openText = fopen("OpenText.txt", "r");
    fread(&block, 8, 1, openText);
    EXPECT_EQ(block, 0x4a98fb2e67a8024c);
    EXPECT_EQ(fgetc(openText), EOF);
    fclose(openText);
}
/*********************************************************/
TEST(ecb, SmallTest4)
{
    char nameInputFile[] = "OpenText.txt";
    char nameOutputFile[] = "CipherText.txt";
    //create open text
    uint64_t block = 0x8912409b17b57e41;
    FILE* openText = fopen("OpenText.txt", "w");
    if(openText == NULL)
    {
        printf("what!!! Where file? (0_0)\n");
    }
    if(fwrite(&block, 8, 1, openText) != 1)
    {
        printf("what?!\n");
    }
    fclose(openText);
    uint32_t key[8]={0xFCFDFEFF, 0xF8F9FAFB, 0xF4F5F6F7, 0xF0F1F2F3, 0x33221100, 0x77665544, 0xBBAA9988, 0xFFEEDDCC};
    //encryption
    EXPECT_EQ(EncryptECB(nameInputFile, nameOutputFile, key, PROC_ADD_NULLS_2), 0);
    //check cipher text
    FILE* cipherText = fopen("CipherText.txt", "r");
    fread(&block, 8, 1, cipherText);
    EXPECT_EQ(block, 0x7c68260996c67efb);
    EXPECT_EQ(feof(cipherText), 0);
    fclose(cipherText);
    //decryption
    EXPECT_EQ(DecryptECB(nameOutputFile, nameInputFile, key, PROC_ADD_NULLS_2, 0), 0);
    //check open text
    openText = fopen("OpenText.txt", "r");
    fread(&block, 8, 1, openText);
    EXPECT_EQ(block, 0x8912409b17b57e41);
    EXPECT_EQ(fgetc(openText), EOF);
    fclose(openText);
}
/*********************************************************/
TEST(imito, CreateHelpingKey)
{
    uint32_t key[8]={0xFCFDFEFF, 0xF8F9FAFB, 0xF4F5F6F7, 0xF0F1F2F3, 0x33221100, 0x77665544, 0xBBAA9988, 0xFFEEDDCC};
    uint32_t ptrOnArrKeys[32];
    createEncryptKeys(ptrOnArrKeys, key);
    EXPECT_EQ(createHelpingKey(ptrOnArrKeys,CREATE_KEY_1), 0x5f459b3342521424);
}
/*********************************************************/
TEST(imito, GetMAC)
{
    char nameInputFile[] = "OpenText.txt";
    //create open text
    uint64_t block = 0x92def06b3c130a59;
    FILE* openText = fopen("OpenText.txt", "w");
    if(openText == NULL)
    {
        printf("what!!! Where file? (0_0)\n");
    }
    if(fwrite(&block, 8, 1, openText) != 1)
    {
        printf("what?!\n");
    }
    block = 0xdb54c704f8189d20;
    if(fwrite(&block, 8, 1, openText) != 1)
    {
        printf("what?!\n");
    }
    block = 0x4a98fb2e67a8024c;
    if(fwrite(&block, 8, 1, openText) != 1)
    {
        printf("what?!\n");
    }
    block = 0x8912409b17b57e41;
    if(fwrite(&block, 8, 1, openText) != 1)
    {
        printf("what?!\n");
    }
    fclose(openText);
    uint32_t key[8]={0xFCFDFEFF, 0xF8F9FAFB, 0xF4F5F6F7, 0xF0F1F2F3, 0x33221100, 0x77665544, 0xBBAA9988, 0xFFEEDDCC};
    EXPECT_EQ(getMAC(nameInputFile, key, 32), 0x154e7210);
}
/*********************************************************/
int main(int argc, char **argv)
{
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
