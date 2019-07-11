#pragma once

#include "stdafx.h"

class Rijndael_GF
{
public:
	static const unsigned char generator = 0x03;	//Generator for logarithms
	static const unsigned int primitive = 0x11B;	//Modulo during multiplications
	static unsigned char log_lookup[256];
	static unsigned char exp_lookup[256];
	static unsigned char inverse_lookup[256];

	unsigned char value;

	Rijndael_GF(unsigned char);
	Rijndael_GF operator+(Rijndael_GF);
	Rijndael_GF operator-(Rijndael_GF);
	Rijndael_GF operator*(Rijndael_GF);
	Rijndael_GF get_inverse();

	~Rijndael_GF();

//private:
	static void generate_exp_log();
	static void generate_inverse();
	//void generate_log();
};
