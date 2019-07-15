CC = icpc

CFLAGS = -O3 -D UBUNTU18_04 -std=c++17 -qopenmp -fp-model fast=2 -parallel -mkl -ffinite-math-only -fma -march=skylake -mtune=skylake -I.

DEPS = stdafx.h
RM = rm
FILE_NAME = AES_Decryption
$FILE_NAME = AES_Encryption

SEPARATOR = /

ifeq ($(OS),Windows_NT)
	FILE_NAME = $(FILE_NAME).exe
	RM = cmd /C del
	SEPARATOR = \\
endif

%.o: %.cpp %.h $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

compile: $(FILE_NAME).cpp AES.o Rijndael_GF.o
	$(CC) $(CFLAGS) -o $(FILE_NAME) $^

clean:
	$(RM) -f *.o
	$(RM) -f $(FILE_NAME)
