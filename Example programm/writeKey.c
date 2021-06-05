#include <stdio.h>

int main()
{
    int key[8]={0xFCFDFEFF, 0xF8F9FAFB, 0xF4F5F6F7, 0xF0F1F2F3, 0x33221100, 0x77665544, 0xBBAA9988, 0xFFEEDDCC};
    FILE* file = fopen("key.key", "w");
    for(int index = 0; index<8; index++)
        fwrite(key+index, 4, 1, file);
    close(file);
    return 1;
}
