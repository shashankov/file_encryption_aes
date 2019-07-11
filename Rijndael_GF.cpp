#include "Rijndael_GF.h"

unsigned char Rijndael_GF::exp_lookup[256] = { 0 };
unsigned char Rijndael_GF::log_lookup[256] = { 0 };
unsigned char Rijndael_GF::inverse_lookup[256] = { 1 };

Rijndael_GF::Rijndael_GF(unsigned char value)
{
	Rijndael_GF::value = value;
}

/* Add two numbers in a GF(2^8) finite field */
Rijndael_GF Rijndael_GF::operator+(Rijndael_GF input)
{
	return Rijndael_GF(input.value ^ value);	//Addition is replaced by the XOR Operation
}

/* Subtract two numbers in a GF(2^8) finite field */
Rijndael_GF Rijndael_GF::operator-(Rijndael_GF input)
{
	return this->operator+(input);
}

/* Multiply two numbers in the GF(2^8) finite field defined
* by the polynomial x^8 + x^4 + x^3 + x + 1 = 0
* using the Russian Peasant Multiplication algorithm
* (the other way being to do carry-less multiplication followed by a modular reduction)
*/
Rijndael_GF Rijndael_GF::operator*(Rijndael_GF input)
{
	unsigned char a = this->value;
	unsigned char b = input.value;

	unsigned char p = 0; /* the product of the multiplication */
	while (b) {
		if (b & 1) /* if b is odd, then add the corresponding a to p (final product = sum of all a's corresponding to odd b's) */
			p ^= a; /* since we're in GF(2^m), addition is an XOR */

		if (a & 0x80) /* GF modulo: if a >= 128, then it will overflow when shifted left, so reduce */
			a = (a << 1) ^ primitive; /* XOR with the primitive polynomial */
		else
			a <<= 1; /* equivalent to a*2 */
		b >>= 1; /* equivalent to b // 2 */
	}
	return Rijndael_GF(p);
}

Rijndael_GF Rijndael_GF::get_inverse()
{
	if (value == 0)
	{
		cerr << "Multiplicative Inverse of 0 does not exist.";
		return Rijndael_GF(0);
	}
	return Rijndael_GF(exp_lookup[255 - int(log_lookup[this->value])]);
}

Rijndael_GF::~Rijndael_GF()
{
	//Empty Destructor
}

void Rijndael_GF::generate_exp_log()
{
	exp_lookup[0] = 1;
	log_lookup[1] = 0;
	for (int i = 1; i < 256; i++)
	{
		exp_lookup[i] = (Rijndael_GF(exp_lookup[i-1]) * Rijndael_GF(generator)).value;
		log_lookup[exp_lookup[i]] = i;
	}
}

void Rijndael_GF::generate_inverse()
{
	inverse_lookup[0] = 0;	//Though mathematically it is undefined it is set for pratical putposes
	for (int i = 1; i < 256; i++)
		inverse_lookup[i] = Rijndael_GF(i).get_inverse().value;
}
