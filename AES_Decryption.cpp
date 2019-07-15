// AES_Encryption.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "semaphore.h"
#include "AES.h"

#ifdef __linux__
#include <sys/ioctl.h>
#endif

#define CHUNK_SIZE ((uint64_t) 4 * 1024)	// 4KB Matching Page Size
#define BUFFER_SIZE (32 * 1024)

vector<pair<unsigned char[CHUNK_SIZE], uint64_t[2]> > buffer;
volatile uint64_t write_head = 0, execute_head = 0, tail = 0;	// Variables for circular queue

bool read_complete = false, work_complete = false;
sem_t s_read, s_work, s_write;	// Semaphore to implement multithreading

double timeTaken;
double prev_progress[] = {-1, -1, -1};
double progress[] = {0, 0, 0};

void update_progress_bar() {
	struct winsize w;
	ioctl(0, TIOCGWINSZ, &w);

	const int fixed = 6;
	uint64_t columns = w.ws_col;
	double unit_progress = min(1.0 / (columns - fixed), 0.01);

	//cout << progress << " " << unit_progress<< endl;
	if (columns <= fixed)
		return;

	bool displayable_progress = false;
	for (int i = 0; i < 3; i++)
		displayable_progress = ((progress[i] - prev_progress[i]) >= unit_progress);
	if (!displayable_progress)
		return;

	for (int i = 0; i < 3; i++)
		prev_progress[i] = progress[i];

	cout <<"\033[1m\r";
	cout << "[\033[32;1m";
	for (int i = 0; i <(columns - fixed); i++) {
		if (i >= progress[0] * (columns - fixed))
			cout << "\033[0m\033[1m";
		else if (i >= progress[1] * (columns - fixed))
			cout << "\033[34;1m";
		else if (i >= progress[2] * (columns - fixed))
			cout << "\033[33m";
		cout << (i < progress[0] * (columns - fixed) ? "■" : ".");
	}

	uint8_t digits[] = {int((progress[2] * 100) / 100), int((progress[2] * 100) / 10) % 10, int((progress[2] * 100)) % 10};
	cout << "]" << (digits[0] ? to_string(digits[0]) : " ") << ((digits[1] || digits[0]) ? to_string(digits[1]) : " ") << to_string(digits[2]) << "%\033[0m" << flush;

	if (progress[2] >= 1)
		cout << "\n";
}

int main(int argc, char *argv[])
{
	if (argc != 3) {
		cerr << "\033[31mError: Incorrect command line arguments.\n"
			"Expected two arguments: File Name (to be decrypted); File Name (decrypted file)\033[0m\n";
		return -1;
	}

	struct stat output;
	stat(argv[1], &output);
	uint64_t input_size = output.st_size - 16*2, output_size = 0, execute_size = 0;
	double input_size_copy = output.st_size - 16*2;

	ifstream ifile(argv[1], ifstream::binary);
	if (!ifile.is_open()) {
		cerr << "\033[31mError: Could not find file - " << argv[1] << "\033[0m\n";
		return -1;
	}

	ofstream ofile(argv[2], ofstream::binary);

	buffer.resize(BUFFER_SIZE);

	// Initialize all semaphores
	bool sem_err = false;
	sem_err = sem_err || (sem_init(&s_read, 0, BUFFER_SIZE) == -1);
	sem_err = sem_err || (sem_init(&s_work, 0, 0) == -1);
	sem_err = sem_err || (sem_init(&s_write, 0, 0) == -1);
	if (sem_err) {
		cerr << "\033[31mError: Could not initialize semaphores.\033[0m\n";
		return -1;
	}

	unsigned char key[16] = {0};

	struct timeval start, end;
	gettimeofday(&start, NULL);

	uint64_t size, size_copy;
	unsigned char* metadata = new unsigned char[16 * 2];
	ifile.read((char *) metadata, 16 * 2);

	AES file(key, false, &size, metadata);
	size_copy = size;

	// OMP Structured Block running in Parallel of 3 threads
	#pragma omp parallel num_threads(3)
	{
		switch(omp_get_thread_num()) {
			case 0:	// Reading Thread
				while(input_size > 0) {
					sem_wait(&s_read);
					ifile.read((char *) buffer[tail].first, min(CHUNK_SIZE, input_size));
					buffer[tail].second[1] = min(CHUNK_SIZE, size);
					buffer[tail].second[0] = min(CHUNK_SIZE, input_size);

					// Ensure the tail comes back to the front
					tail = (tail + 1) % BUFFER_SIZE;

					input_size -= min(CHUNK_SIZE, input_size);
					size -= min(CHUNK_SIZE, size);

					progress[0] = 1.0 - ((double) input_size) / input_size_copy;
					update_progress_bar();

					sem_post(&s_work);
				}
				cout << "File read complete. Signalling other threads.\n";
				read_complete = true;

				// Following will allow the encrypter thread to exit
				sem_post(&s_work);
				break;
			case 1:	// Encryption Thread
				while(true) {
					sem_wait(&s_work);

					int work_left;
					sem_getvalue(&s_work, &work_left);
					if (read_complete && (work_left == 0))
						break;

					file.decrypt(buffer[execute_head].first, buffer[execute_head].second[0]);

					execute_size += buffer[execute_head].second[0];
					progress[1] = ((double) execute_size) / input_size_copy;
					update_progress_bar();

					// Ensure the head comes back to the front
					execute_head = (execute_head + 1) % BUFFER_SIZE;
					sem_post(&s_write);
				}
				cout << "File decryption complete. Thread exiting.\n";
				work_complete = true;

				// Following will allow the writer thread to exit
				sem_post(&s_write);
				break;
			case 2:	// Write Back Thread
				while(true) {
					sem_wait(&s_write);

					int write_left;
					sem_getvalue(&s_write, &write_left);
					if (work_complete && (write_left == 0))
						break;

					ofile.write((char *) buffer[write_head].first, buffer[write_head].second[1]);

					output_size += buffer[write_head].second[1];
					progress[2] = ((double) output_size) / size_copy;
					update_progress_bar();

					// Ensure the head comes back to the front
					write_head = (write_head + 1) % BUFFER_SIZE;
					sem_post(&s_read);
				}
				cout << "Decrypted file write complete. Thread exiting.\n";
				break;
			default:
				cerr << "\033[33mWarning: Extra thread created. Nothing to do.\033[0m\n";
		}
	}
	gettimeofday(&end, NULL);

	timeTaken = end.tv_sec - start.tv_sec + 1E-6 * (end.tv_usec - start.tv_usec);
	ifile.close();
	ofile.close();

	string size_units[] = {"B", "kB", "MB", "GB", "TB"};
	uint8_t size_type = 0;
	while(input_size_copy > 1024) {
		input_size_copy = input_size_copy / 1024;
		size_type++;
	}

	cout << "Decrypted file: " << argv[1] << ", of size " << input_size_copy << size_units[size_type] << " in time: " << timeTaken << "\n";
}
