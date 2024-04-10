/* encrypt.cpp
 * Performs encryption using AES 128-bit
 * @author Cecelia Wisniewska
 */

#include <iostream>
#include <cstring>
#include <fstream>
#include <sstream>
#include <omp.h>
#include "structures.h"

using namespace std;

int INN_THREAD_NUM = 4;

/* Serves as the initial round during encryption
 * AddRoundKey is simply an XOR of a 128-bit block with the 128-bit key.
 */
void AddRoundKey(unsigned char * state, const unsigned char * roundKey, int st, int ed) {
	for (int i = st; i < ed; i++) {
		state[i] ^= roundKey[i];
	}
}

/* Perform substitution to each of the 16 bytes
 * Uses S-box as lookup table 
 */
void SubBytes(unsigned char * state, int st, int ed) {
	for (int i = st; i < ed; i++) {
		state[i] = s[state[i]];
	}
}

 /* MixColumns uses mul2, mul3 look-up tables
  * Source of diffusion
  */
void MixColumns(unsigned char * sta, int st, int ed) {
	unsigned char tmp[16];

	for (int i=st; i<ed; i++) {
		if((i%4) == 0) tmp[i] = (unsigned char) mul2[sta[i]] ^ mul3[sta[i+1]] ^ sta[i+2] ^ sta[i+3];
		else if((i%4) == 1) tmp[i] = (unsigned char) sta[i-1] ^ mul2[sta[i]] ^ mul3[sta[i+1]] ^ sta[i+2];
		else if((i%4) == 2) tmp[i] = (unsigned char) sta[i-2] ^ sta[i-1] ^ mul2[sta[i]] ^ mul3[sta[i+1]];
		else if((i%4) == 3) tmp[i] = (unsigned char) mul3[sta[i-3]] ^ sta[i-2] ^ sta[i-1] ^ mul2[sta[i]];
	} 

	for (int i = st; i < ed; i++) {
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
		
		AddRoundKey(state, expandedKey, start, end);
		#pragma omp barrier
		
	
		for (int i = 0; i < numberOfRounds; i++) {
			#pragma omp barrier
			SubBytes(state, start, end);
			#pragma omp barrier
			unsigned char tmp[16];
			for (int s=start; s<end; s++) {
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
			for (int s = start; s < end; s++) {
				state[s] = tmp[s];
			}
			#pragma omp barrier
			MixColumns(state, start, end);
			#pragma omp barrier
			AddRoundKey(state, expandedKey + (16 * (i+1)), start, end);
		}

		#pragma omp barrier
		SubBytes(state, start, end);

		#pragma omp barrier
		unsigned char tmp[16];
		for (int i=start; i<end; i++) {
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
		for (int i = start; i < end; i++) {
			state[i] = tmp[i];
		}
		#pragma omp barrier
		AddRoundKey(state, expandedKey + 160, start, end);
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

	char message[1024];

	cout << "Enter the message to encrypt: ";
	cin.getline(message, sizeof(message));
	cout << message << endl;

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

	for (int i = 0; i < paddedMessageLen; i += 16) {
		AESEncrypt(paddedMessage+i, expandedKey, encryptedMessage+i);
	}

	cout << "Encrypted message in hex:" << endl;
	for (int i = 0; i < paddedMessageLen; i++) {
		cout << hex << (int) encryptedMessage[i];
		cout << " ";
	}

	cout << endl;

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