/* encrypt.cpp
 * Performs encryption using AES 128-bit
 * @author Cecelia Wisniewska
 */

#include <iostream>
#include <cstring>
#include <fstream>
#include <sstream>
#include <omp.h>
#include <time.h>
#include "structures.h"

using namespace std;

int OUT_THREAD_NUM = 4;
int INN_THREAD_NUM = 16;

/* Serves as the initial round during encryption
 * AddRoundKey is simply an XOR of a 128-bit block with the 128-bit key.
 */
void AddRoundKey(unsigned char * state, const unsigned char * roundKey, int st) {
	for (int i = 0; i < 16; i++) {
		state[st] ^= roundKey[st];
		st++;
	}
}

/* Perform substitution to each of the 16 bytes
 * Uses S-box as lookup table 
 */
void SubBytes(unsigned char * state, int st) {
	for (int i = 0; i < 16; i++) {
		state[st] = s[state[st]];
		st++;
	}
}

 /* MixColumns uses mul2, mul3 look-up tables
  * Source of diffusion
  */
void MixColumns(unsigned char * sta, int st) {
	unsigned char tmp[16];

	for (int i=st; i<(st+16); i++) {
		if((i%4) == 0) tmp[i] = (unsigned char) mul2[sta[i]] ^ mul3[sta[i+1]] ^ sta[i+2] ^ sta[i+3];
		else if((i%4) == 1) tmp[i] = (unsigned char) sta[i-1] ^ mul2[sta[i]] ^ mul3[sta[i+1]] ^ sta[i+2];
		else if((i%4) == 2) tmp[i] = (unsigned char) sta[i-2] ^ sta[i-1] ^ mul2[sta[i]] ^ mul3[sta[i+1]];
		else if((i%4) == 3) tmp[i] = (unsigned char) mul3[sta[i-3]] ^ sta[i-2] ^ sta[i-1] ^ mul2[sta[i]];
	} 

	for (int i = st; i < (st+16); i++) {
		sta[i] = tmp[i];
	}
}

/* The AES encryption function
 * Organizes the confusion and diffusion steps into one function
 */
void AESEncrypt(unsigned char * message, unsigned char * expandedKey, unsigned char * encryptedMessage) {
	unsigned char * state = new unsigned char[16];

	for (int i = 0; i < 16; i++) {
		state[i] = message[i];
	}
	

	int numberOfRounds = 9;

	int thread_num = INN_THREAD_NUM;
	int chunk = 16/thread_num;
	int tid,start,end;
	
	

	omp_set_num_threads(thread_num);
	#pragma omp parallel shared(chunk) private(tid,start,end)
	{
        tid = omp_get_thread_num();
		start = tid*chunk;
		end = (tid+1)*chunk;
		
		AddRoundKey(state, expandedKey, start);
		#pragma omp barrier
		
	
		for (int i = 0; i < numberOfRounds; i++) {
			#pragma omp barrier
			SubBytes(state, start);
			#pragma omp barrier
			unsigned char tmp[16];
			for (int s=start; s<(start+16); s++) {
				int temp_idx =s;
				if((s%4) == 0){

				}
				else if((s%4) == 1){
					temp_idx += 4;
					if (temp_idx > 13) temp_idx = 1;
				}
				else if((s%4) == 2){
					temp_idx += 8;
					if (temp_idx > 14) temp_idx -= 16;
				}
				else if((s%4) == 3){
					temp_idx += 12;
					if (temp_idx > 15) temp_idx -= 16;
				}
				tmp[s] = state[temp_idx];
			}
			#pragma omp barrier
			for (int s = start; s < (start+16); s++) {
				state[s] = tmp[s];
			}
			#pragma omp barrier

			MixColumns(state, start);
			#pragma omp barrier
	
			AddRoundKey(state, expandedKey + (16 * (i+1)), start);
		}

		#pragma omp barrier
		SubBytes(state, start);

		#pragma omp barrier
		unsigned char tmp[16];
		for (int i=start; i<(start+16); i++) {
			int temp_idx =i;
			if((i%4) == 0){

			}
			else if((i%4) == 1){
				temp_idx += 4;
				if (temp_idx > 13) temp_idx = 1;
			}
			else if((i%4) == 2){
				temp_idx += 8;
				if (temp_idx > 14) temp_idx -= 16;
			}
			else if((i%4) == 3){
				temp_idx += 12;
				if (temp_idx > 15) temp_idx -= 16;
			}
			tmp[i] = state[temp_idx];
		}
		#pragma omp barrier
		for (int i = start; i < (start+16); i++) {
			state[i] = tmp[i];
		}
		#pragma omp barrier
		AddRoundKey(state, expandedKey + 160, start);
	}	

	// Copy encrypted state to buffer
	for (int i = 0; i < 16; i++) {
		encryptedMessage[i] = state[i];
	}
	delete[] state;
}

int main() {
	cout << "=============================" << endl;
	cout << " 128-bit AES Encryption Tool   " << endl;
	cout << "=============================" << endl;

	char message[102400];

	for(int z=0; z<102400; z++){
		message[z] = 'h';
	}

	// Pad message to 16 bytes
	int originalLen = strlen((const char *)message);

	int paddedMessageLen = originalLen;

	if ((paddedMessageLen % 16) != 0) {
		paddedMessageLen = (paddedMessageLen / 16 + 1) * 16;
	}

	unsigned char * paddedMessage = new unsigned char[paddedMessageLen];
	for (int i = 0; i < paddedMessageLen; i++) {
		if (i >= originalLen) {
			paddedMessage[i] = 0;
		}
		else {
			paddedMessage[i] = message[i];
		}
	}

	unsigned char * encryptedMessage = new unsigned char[paddedMessageLen];

	string str;
	ifstream infile;
	infile.open("keyfile", ios::in | ios::binary);

	if (infile.is_open())
	{
		getline(infile, str); // The first line of file should be the key
		infile.close();
	}

	else cout << "Unable to open file";

	istringstream hex_chars_stream(str);
	unsigned char key[16];
	int i = 0;
	unsigned int c;
	while (hex_chars_stream >> hex >> c)
	{
		key[i] = c;
		i++;
	}

	unsigned char expandedKey[176];

	KeyExpansion(key, expandedKey);

	int it, chunk, tid;
	int sz = paddedMessageLen/16;
	omp_set_num_threads(4);
	chunk = 1;

	struct timespec start, stop; 
	double time;

	if( clock_gettime(CLOCK_REALTIME, &start) == -1) { perror("clock gettime");}

	#pragma omp parallel shared(chunk) private(it,tid)
	{
		#pragma omp for schedule(static, chunk)nowait
		for (it = 0; it < sz; it++) {
			AESEncrypt(paddedMessage+(it*16), expandedKey, encryptedMessage+(it*16));
		}
	}	

	if( clock_gettime( CLOCK_REALTIME, &stop) == -1 ) { perror("clock gettime");}		
	time = (stop.tv_sec - start.tv_sec)+ (double)(stop.tv_nsec - start.tv_nsec)/1e9;
	printf("Execution time = %f sec\n", time);	



	// Write the encrypted string out to file "message.aes"
	ofstream outfile;
	outfile.open("message.aes", ios::out | ios::binary);
	if (outfile.is_open())
	{
		outfile << encryptedMessage;
		outfile.close();
		cout << "Wrote encrypted message to file message.aes" << endl;
	}

	else cout << "Unable to open file";

	// Free memory
	delete[] paddedMessage;
	delete[] encryptedMessage;

	return 0;
}