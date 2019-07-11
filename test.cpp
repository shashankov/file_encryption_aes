#include "stdafx.h"
#include "AES.h"

double timeTaken;

int main() {
    unsigned char test[4][4] = { {0, 0, 0, 0}, {1, 2, 3, 4}, {2, 3, 4, 5}, {10, 10, 10, 10}};
    unsigned char key[16] = {0};

    unsigned char metadata[16];
    uint64_t size = 16;

    AES file(key, true, &size, metadata);
    file.encrypt_block(test);
    file.decrypt_block(test);

    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            cout << (int)test[i][j] << endl;
}