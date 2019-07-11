#include "AES.h"

unsigned char AES::S_Box[256] = { 0 };
unsigned char AES::inverse_S_Box[256] = { 0 };
unsigned char AES::rcon[256] = { 0 };
unsigned char AES::mul_table[6][256] = { { 1 } };
unsigned char round_keys_256[15][16];
const unsigned char AES::mul_nums[6] = { 2, 3, 9, 11, 13, 14 };

unsigned char prev_data[16];

void AES::generate_S_Box()
{
	for (int iterator = 0; iterator < 256; iterator++)
	{
		unsigned char s = Rijndael_GF::inverse_lookup[iterator], x = s;
		for (int loop = 0; loop < 4; loop++)
		{
			s = (s << 1) + ((s >= 128)?1:0);
			x = x ^ s;
		}
		S_Box[iterator] = x ^ 0x63;
		inverse_S_Box[x ^ 0x63] = iterator;
	}
}

void AES::generate_rcon()
{
	Rijndael_GF rcon_base = Rijndael_GF(2);
	rcon[1] = 1;
	for (int i = 2; i < 256; i++)
		rcon[i] = (rcon_base * Rijndael_GF(rcon[i - 1])).value;
	rcon[0] = (rcon_base * Rijndael_GF(rcon[255])).value;
}

void AES::generate_mul_tables()
{
	for (int i = 0; i < 6; i++)
	{
		Rijndael_GF num = Rijndael_GF(mul_nums[i]);
		for (int j = 0; j < 256; j++)
			mul_table[i][j] = (num * Rijndael_GF(j)).value;
	}
}

void AES::Rijndael_Key_Core(unsigned char* io, uint8_t iteration)
{
	//Perform the rotate
	unsigned char temp = io[3];
	io[3] = io[2];
	io[2] = io[1];
	io[1] = io[0];
	io[0] = temp;

	//Use the Substitution Box
	for (int i = 0; i < 4; i++)
		io[i] = S_Box[io[i]];

	//Apply RCON XOR Operation
	io[3] = io[3] ^ rcon[iteration];
}

void AES::expand_key(unsigned char *key, unsigned char extended_key_array[][16])
{
	const uint16_t EXTENDED_LENGTH = NUM_KEYS * 4;
	unsigned char* output = new unsigned char [EXTENDED_LENGTH * 4];

	for (int i = 0; i < KEY_LENGTH * 32; i++)
		output[i] = key[i];

	for (int word_index = KEY_LENGTH; word_index < EXTENDED_LENGTH; word_index++)
	{
		unsigned char next[4];
		for (int i = 0; i < 4; i++)
			next[i] = output[(word_index - 1) * 4 + i];
		//Depends on the key size
		if ((word_index % KEY_LENGTH) == 0)
			Rijndael_Key_Core(next, word_index/KEY_LENGTH);

		#if KEY_SIZE == 256
		else if (word_index % KEY_LENGTH == 4)
			for (int i = 0; i < 4; i++)
				next[i] = S_Box[next[i]];
		#endif

		//Done for all key sizes
		for (int i = 0; i < 4; i++)
			output[word_index * 4 + i] = next[i] ^
				output[(word_index - KEY_LENGTH) * 4 + i];
	}

	for (int i = 0; i < NUM_KEYS; i++)
		for (int j = 0; j < 16; j++)
			extended_key_array[i][j] = output[i*16 + j];

	delete[] output;
}

void AES::subBytes(unsigned char input[4][4])
{
	//Substitution Using the S BOX
	//Input 4x4 matrix of bytes representing the 128 bits
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			input[i][j] = S_Box[input[i][j]];
}

void AES::inverseSubBytes(unsigned char input[4][4])
{
	//Substitution Using the S BOX
	//Input 4x4 matrix of bytes representing the 128 bits
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			input[i][j] = inverse_S_Box[input[i][j]];
}

void AES::shiftRows(unsigned char input[4][4])
{
	for (int i = 0; i < 4; i++)
	{
		unsigned char temp[4] = { 0 };
		for (int j = 0; j < 4; j++)
			temp[(4 + j - i) % 4] = input[i][j];

		for (int j = 0; j < 4; j++)
			input[i][j] = temp[j];
	}
}


void AES::inverseShiftRows(unsigned char input[4][4])
{
	for (int i = 0; i < 4; i++)
	{
		unsigned char temp[4] = { 0 };
		for (int j = 0; j < 4; j++)
			temp[(j + i) % 4] = input[i][j];

		for (int j = 0; j < 4; j++)
			input[i][j] = temp[j];
	}
}

void AES::mixColumns(unsigned char input[4])
{
	unsigned char input0[4], input1[4], input2[4], input3[4];
	for (int i = 0; i < 4; i++)
	{
		input0[i] = mul_table[0][input[i]];
		input1[i] = mul_table[1][input[i]];
		input2[i] = input[i];
		input3[i] = input[i];
	}
	input[0] = input0[0] ^ input1[1] ^ input2[2] ^ input3[3];
	input[1] = input3[0] ^ input0[1] ^ input1[2] ^ input2[3];
	input[2] = input2[0] ^ input3[1] ^ input0[2] ^ input1[3];
	input[3] = input1[0] ^ input2[1] ^ input3[2] ^ input0[3];
}

void AES::inverseMixColumns(unsigned char input[4])
{
	unsigned char input0[4], input1[4], input2[4], input3[4];
	for (int i = 0; i < 4; i++)
	{
		input0[i] = mul_table[5][input[i]];
		input1[i] = mul_table[3][input[i]];
		input2[i] = mul_table[4][input[i]];
		input3[i] = mul_table[2][input[i]];
	}
	input[0] = input0[0] ^ input1[1] ^ input2[2] ^ input3[3];
	input[1] = input3[0] ^ input0[1] ^ input1[2] ^ input2[3];
	input[2] = input2[0] ^ input3[1] ^ input0[2] ^ input1[3];
	input[3] = input1[0] ^ input2[1] ^ input3[2] ^ input0[3];
}

void AES::round_encrypt(unsigned char io[4][4], unsigned char round_key[16])
{
	subBytes(io);
	shiftRows(io);
	for (int i = 0; i < 4; i++)
	{
		unsigned char column[4] = { io[0][i],io[1][i],io[2][i],io[3][i] };
		mixColumns(column);
		for (int j = 0; j < 4; j++)
			io[j][i] = column[j];
	}
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			io[i][j] = io[i][j] ^ round_key[i * 4 + j];
}

void AES::round_encrypt_last(unsigned char io[4][4], unsigned char round_key[16])
{
	subBytes(io);
	shiftRows(io);
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			io[i][j] = io[i][j] ^ round_key[i * 4 + j];
}

void AES::round_decrypt(unsigned char io[4][4], unsigned char round_key[16])
{
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			io[i][j] = io[i][j] ^ round_key[i * 4 + j];

	for (int i = 0; i < 4; i++)
	{
		unsigned char column[4] = { io[0][i],io[1][i],io[2][i],io[3][i] };
		inverseMixColumns(column);
		for (int j = 0; j < 4; j++)
			io[j][i] = column[j];
	}
	inverseShiftRows(io);
	inverseSubBytes(io);
}

void AES::round_decrypt_first(unsigned char io[4][4], unsigned char round_key[16])
{
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			io[i][j] = io[i][j] ^ round_key[i * 4 + j];

	inverseShiftRows(io);
	inverseSubBytes(io);
}

void AES::encrypt_block(unsigned char io[4][4])
{
	uint8_t round = 0;
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			io[i][j] = io[i][j] ^ round_keys[round][i * 4 + j];
	round++;

	for (; round < NUM_KEYS - 1; round++)
		round_encrypt(io, round_keys[round]);
	round_encrypt_last(io, round_keys[round]);
}

void AES::decrypt_block(unsigned char io[4][4])
{
	uint8_t round = NUM_KEYS - 1;
	round_decrypt_first(io, round_keys[round]);
	round--;

	for (; round > 0; round--)
		round_decrypt(io, round_keys[round]);

	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			io[i][j] = io[i][j] ^ round_keys[round][i * 4 + j];
}

void AES::int_to_array(uint64_t input, unsigned char *output)
{
	for (int i = 0; i < 8; i++)
	{
		output[i] = input % 256;
		input = input >> 8;
	}
}

void AES::encrypt(unsigned char *message, int size)
{
	const int num_blocks = size / 16;
	uint64_t counter;
	memcpy((void *) &counter, (void *) &prev_data[8], 8);

	unsigned char block_io[4][4];

	for (int i = 0; i < num_blocks; i++) {

		// Prepare Block for Encryption
		for (int j = 0; j < 4; j++) {
			for (int k = 0; k < 4; k++) {
			#if ECB
				block_io[j][k] = message[i * 16 + j * 4 + k];
			#elif CBC || PCBC
				block_io[j][k] = message[i * 16 + j * 4 + k] ^ prev_data[j * 4 + k];
			#else // CFB, OFB, and CTR
				block_io[j][k] = prev_data[j * 4 + k];
			#endif
			}
		}

		// Perform the Encryption
		encrypt_block(block_io);

		// Prepare the Previous Data Block for the next round
		// and the ciphertext simultaneously
		for (int j = 0; j < 4; j++) {
			for (int k = 0; k < 4; k++) {
				#if ECB
					//Nothing to be stored
					message[i * 16 + j * 4 + k] = block_io[j][k];
				#elif CBC
					prev_data[j * 4 + k] = block_io[j][k];
					message[i * 16 + j * 4 + k] = block_io[j][k];
				#elif PCBC
					prev_data[j * 4 + k] = block_io[j][k] ^ message[i * 16 + j * 4 + k];
					message[i * 16 + j * 4 + k] = block_io[j][k];
				#elif CFB
					message[i * 16 + j * 4 + k] = message[i * 16 + j * 4 + k] ^ block_io[j][k];
					prev_data[j * 4 + k] = message[i * 16 + j * 4 + k];
				#elif OFB
					message[i * 16 + j * 4 + k] = message[i * 16 + j * 4 + k] ^ block_io[j][k];
					prev_data[j * 4 + k] = block_io[j][k];
				#else // CTR
					message[i * 16 + j * 4 + k] = message[i * 16 + j * 4 + k] ^ block_io[j][k];
					memcpy((void *) &prev_data[8], (void *) &(++counter), 8));
				#endif
			}
		}
	}
}

void AES::decrypt(unsigned char *message, int size)
{
	const int num_blocks = size / 16;
	uint64_t counter = *((uint64_t *) &prev_data[8]);

	unsigned char block_io[4][4];

	for (int i = 0; i < num_blocks; i++) {

		// Prepare Block for Encryption
		for (int j = 0; j < 4; j++) {
			for (int k = 0; k < 4; k++) {
			#if ECB || CBC || PCBC
				block_io[j][k] = message[i * 16 + j * 4 + k];
			#else // CFB, OFB, and CTR
				block_io[j][k] = prev_data[j * 4 + k];
			#endif
			}
		}

		// Perform the Encryption/Decryption
		#if ECB || CBC || PCBC
			decrypt_block(block_io);
		#else // CFB, OFB, and CTR
			encrypt_block(block_io);
		#endif

		// Prepare the Previous Data Block for the next round
		// and the plaintext simultaneously
		for (int j = 0; j < 4; j++) {
			for (int k = 0; k < 4; k++) {
				#if ECB
					//Nothing to be stored
					message[i * 16 + j * 4 + k] = block_io[j][k];
				#elif CBC
					unsigned char temp = prev_data[j * 4 + k];
					prev_data[j * 4 + k] = message[i * 16 + j * 4 + k];
					message[i * 16 + j * 4 + k] = temp ^ block_io[j][k];
				#elif PCBC
					unsigned char temp = message[i * 16 + j * 4 + k];
					message[i * 16 + j * 4 + k] = prev_data[j * 4 + k] ^ block_io[j][k];
					prev_data[j * 4 + k] = temp ^ message[i * 16 + j * 4 + k];
				#elif CFB
					prev_data[j * 4 + k] = message[i * 16 + j * 4 + k];
					message[i * 16 + j * 4 + k] = message[i * 16 + j * 4 + k] ^ block_io[j][k];
				#elif OFB
					message[i * 16 + j * 4 + k] = message[i * 16 + j * 4 + k] ^ block_io[j][k];
					prev_data[j * 4 + k] = block_io[j][k];
				#else // CTR
					message[i * 16 + j * 4 + k] = message[i * 16 + j * 4 + k] ^ block_io[j][k];
					*((uint64_t *) &prev_data[8]) = ++counter;
				#endif
			}
		}
	}
}

AES::AES(unsigned char *key, bool encrypt, uint64_t *size, unsigned char *metadata)
{
	srand(time(NULL));

	//Prepare All Matrices
	Rijndael_GF::generate_exp_log();
	Rijndael_GF::generate_inverse();

	AES::generate_mul_tables();
	AES::generate_rcon();
	AES::generate_S_Box();

	AES::expand_key(key, round_keys);

	unsigned char IV[16], size_array[16];
	unsigned char block_io[4][4];

	if (encrypt) {
		int_to_array(rand(), &IV[0]);
		int_to_array(rand(), &IV[8]);

		int_to_array(*size, &size_array[0]);
		int_to_array(rand(), &size_array[8]);

		for (int i = 0; i < 4; i++)
			for (int j = 0; j < 4; j++)
				block_io[i][j] = IV[i * 4 + j];
		encrypt_block(block_io);
		for (int i = 0; i < 4; i++)
			for (int j = 0; j < 4; j++) {
				metadata[i * 4 + j] = block_io[i][j];
				block_io[i][j] = size_array[i * 4 + j];
			}
		encrypt_block(block_io);
		for (int i = 0; i < 4; i++)
			for (int j = 0; j < 4; j++)
				metadata[16 + i * 4 + j] = block_io[i][j];
	}
	else {
		for (int i = 0; i < 4; i++)
			for (int j = 0; j < 4; j++)
				block_io[i][j] = metadata[16 + i * 4 + j];
		decrypt_block(block_io);
		for (int i = 0; i < 4; i++)
			for (int j = 0; j < 4; j++) {
				size_array[i * 4 + j] = block_io[i][j];
				block_io[i][j] = metadata[i * 4 + j];
			}
		decrypt_block(block_io);
		for (int i = 0; i < 4; i++)
			for (int j = 0; j < 4; j++)
				IV[16 + i * 4 + j] = block_io[i][j];

		memcpy((void *) size, (void * ) size_array, 8);
	}

	// Prepare Previous Data
	memcpy((void *) prev_data, (void *) IV, 16);
}


AES::~AES()
{
	//Empty Destructor. No Instance Pointers exist.
}
