#include "../Magma/Magma.h"
//#include <string.h>
/*********************************************************/
int parameterDefinition(char* prm);
int strEQ(char* strFirst,char * strSecond);
int modeDefinition(char* mode);
/*********************************************************/
uint64_t main(int argc, char** argv)
/*parameters: 
*  -i "name input file" № 1
*  -o "name output file" № 2
*  -k "name file with key" № 3
*  -m "mode" {"ECB", "IMITO"} № 4
*  -p "mode padding" {1-3} № 5
*  -c "encrypt or decrypt" {e, d} № 6
*  -b "count byte in last block" {1-8} № 7
*  -s "size MAC" {1-64} № 8
*  -h "help" № 9
*/
{
    //standard parameters
    char stdNameOutputFile[] = "output.txt";
    char* nameInputFile = NULL;
    char* nameOutputFile = stdNameOutputFile;
    char* nameFileWithKey = NULL;
    int mode = ECB;
    int modePadding = PROC_ADD_NULLS_2;
    int crypt = 'e';
    uint8_t countByteInLastBlock = 0; 
    uint8_t sizeMAC  = 32; 
    //read input parameters
    for(int index = 1; index < argc; index++)
    {
        switch(parameterDefinition(argv[index]))
        {
            case 1: 
                index++;
                if(argv[index] == NULL)
                {
                    printf("fatal error: empty parameter\n");
                    return 0;
                }
                nameInputFile = argv[index];
                break;
            case 2: 
                index++;
                if(argv[index] == NULL)
                {
                    printf("fatal error: empty parameter\n");
                    return 0;
                }
                nameOutputFile = argv[index];
                break;
            case 3: 
                index++;
                if(argv[index] == NULL)
                {
                    printf("fatal error: empty parameter\n");
                    return 0;
                }
                nameFileWithKey = argv[index];
                break;
            case 4: 
                index++;
                if(argv[index] == NULL)
                {
                    printf("fatal error: empty parameter\n");
                    return 0;
                }
                if((mode = modeDefinition(argv[index])) == 0)
                {
                    printf("fatal error: unknown mode\n");
                    return 0;
                }
                if(mode == 6 || mode == 1)
                {
                    break;    
                }
                else
                {
                    printf("fatal error: invalid mode\n");
                    return 0;
                }
            case 5: 
                index++;
                if(argv[index] == NULL)
                {
                    printf("fatal error: empty parameter\n");
                    return 0;
                }
                modePadding = *(argv[index]) - '1' + 1;
                if(modePadding >= 1 && modePadding <=3)
                {
                    break;
                }
                else
                {
                    printf("fatal error: invalid modePadding\n");
                    return 0;
                }
            case 6: 
                index++;
                if(argv[index] == NULL)
                {
                    printf("fatal error: empty parameter\n");
                    return 0;
                }
                crypt = *(argv[index]);
                if(crypt != 'e' && crypt != 'd')
                {
                    printf("fatal error: invalid mode crypt\n");
                    return 0;
                }
                break;
             case 7: 
                index++;
                if(argv[index] == NULL)
                {
                    printf("fatal error: empty parameter\n");
                    return 0;
                }
                countByteInLastBlock = *(argv[index]) - '1' + 1;
                if(countByteInLastBlock <= 8 && countByteInLastBlock >= 1)
                {
                    break;    
                }
                else
                {
                    printf("fatal error: invalid countByteInLastBlock\n");
                    return 0;
                }
            case 8: 
                index++;
                if(argv[index] == NULL)
                {
                    printf("fatal error: empty parameter\n");
                    return 0;
                }
                sizeMAC = (uint8_t)atoi(argv[index]);
                if(sizeMAC <= 64 && sizeMAC >= 1)
                {
                    break;    
                }
                else
                {
                    printf("fatal error: invalid sizeMAC\n");
                    return 0;
                }
            case 9:
                printf("Parameters:\n*  -i name input file\n*  -o name output file\n*  -k name file with key\n*  -m mode {ECB, IMITO}\n*  -p mode padding {1-3}\n*  -c encrypt or decrypt {e, d}\n*  -b count byte in last block {1-8}\n*  -s size MAC {1-64}\n*  -h help\n");
                return 1;
            case -1: 
                printf("fatal error: invalid parameter\n");
                return 0;
        }
    }
    //check
    if(nameInputFile == NULL && nameFileWithKey == NULL)
    {
        printf("fatal error: insufficient parameters\n");
        return 0;
    }
    //read key
    uint32_t key[8];
    FILE* fileWithKey = fopen(nameFileWithKey, "r");
    if(fileWithKey == NULL)
    {
        printf("fatal error: could not open file with key\n");
        return 0;
    }
    if(fread(key, 4, 8, fileWithKey) != 8)
    {
        printf("fatal error: could not read file with key\n");
        return 0;
    }
    fclose(fileWithKey);
    //begin
    switch(mode)
    {
        case ECB:
           if(crypt == 'e')
           {
               if(EncryptECB(nameInputFile, nameOutputFile, key, modePadding) != 1)
               {
                    printf("fatal error: failed to complete EncryptECB");
                    return 0;
               }
           }
           else
           {
                if(DecryptECB(nameInputFile, nameOutputFile, key, modePadding, countByteInLastBlock) != 1)
               {
                    printf("fatal error: failed to complete DecryptECB");
                    return 0;
               }
           }
           break;
        case IMITO:
           {
           uint64_t result = getMAC(nameInputFile, key, sizeMAC);
           printf("%lld\n", result);
           return result;
           }
    }
    return 1;
}
/*********************************************************/
int parameterDefinition(char* prm)
{
    if(*prm != '-')
    {
        return -1;
    }
    switch(prm[1])
    {
        case 'i': 
            if(prm[2] != 0)
            {
                return -1;
            }
            return 1;
        case 'o': 
            if(prm[2] != 0)
            {
                return -1;
            }
            return 2;
        case 'k': 
            if(prm[2] != 0)
            {
                return -1;
            }
            return 3;
        case 'm': 
            if(prm[2] != 0)
            {
                return -1;
            }
            return 4;
        case 'p': 
            if(prm[2] != 0)
            {
                return -1;
            }
            return 5;
        case 'c': 
            if(prm[2] != 0)
            {
                return -1;
            }
            return 6;
        case 'b': 
            if(prm[2] != 0)
            {
                return -1;
            }
            return 7;
        case 's': 
            if(prm[2] != 0)
            {
                return -1;
            }
            return 8;
        case 'h': 
            if(prm[2] != 0)
            {
                return -1;
            }
            return 9;
        default: return -1;
    }
}
/*********************************************************/
int strEQ(char* strFirst,char * strSecond)
{
    int index = 0;
    while(strFirst[index] == strSecond[index])
    {
        if(strFirst[index] == '\0')
        {
            return 1;
        }
        index++;
    }
    //else
    return 0;
}
/*********************************************************/
int modeDefinition(char* mode)
{
    if(strEQ(mode, "ECB"))
    {
        return ECB;
    }
    else if(strEQ(mode, "IMITO"))
    {
        return IMITO;
    }
    return 0;
}
/*********************************************************/
