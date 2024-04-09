#include <iostream>
#include <cstring>
#include <fstream>
#include <sstream>
#include <stdio.h>
#include "structures.h"

using namespace std;

const int num_block = 4;

__global__ void Mixcol(unsigned char *tmp, unsigned char *sta, unsigned char *mul2g, unsigned char *mul3g, int n){
	int st = threadIdx.x*n;
	int ed = st+n;

	for (int i=st; i<ed; i++) {
		if((i%4) == 0) tmp[i] = (unsigned char) mul2g[sta[i]] ^ mul3g[sta[i+1]] ^ sta[i+2] ^ sta[i+3];
		else if((i%4) == 1) tmp[i] = (unsigned char) sta[i-1] ^ mul2g[sta[i]] ^ mul3g[sta[i+1]] ^ sta[i+2];
		else if((i%4) == 2) tmp[i] = (unsigned char) sta[i-2] ^ sta[i-1] ^ mul2g[sta[i]] ^ mul3g[sta[i+1]];
		else if((i%4) == 3) tmp[i] = (unsigned char) mul3g[sta[i-3]] ^ sta[i-2] ^ sta[i-1] ^ mul2g[sta[i]];
	} 
}

__global__ void Subbyt(unsigned char *a, unsigned char *b, int n){
	int st = threadIdx.x*n;
	int ed = st+n;
	
	for (int i=st; i<ed; i++) {
		a[i] = b[a[i]];
	} 
}

__global__ void ShiftRw(unsigned char *a, unsigned char *b, int n){
	int st = threadIdx.x*n;
	int ed = st+n;
	int temp_idx;

	for (int i=st; i<ed; i++) {
		temp_idx =i;
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
		b[i] = a[temp_idx];
	} 
}

__global__ void AddRKey(unsigned char *a, unsigned char *b, int n){
	int st = threadIdx.x*n;
	int ed = st+n;
	
	for (int i=st; i<ed; i++) {
		a[i] ^= b[i];
	} 
}

/* Serves as the initial round during encryption
 * AddRoundKey is simply an XOR of a 128-bit block with the 128-bit key.
 */
void AddRoundKey(unsigned char * state, unsigned char * roundKey) {
	unsigned char *gpu_st, *gpu_rk;
	cudaMalloc((void**)&gpu_st, sizeof(unsigned char)*16); 
	cudaMalloc((void**)&gpu_rk, sizeof(unsigned char)*16);

	cudaMemcpy(gpu_st, state, sizeof(unsigned char)*16, cudaMemcpyHostToDevice);
	cudaMemcpy(gpu_rk, roundKey, sizeof(unsigned char)*16, cudaMemcpyHostToDevice);
	AddRKey<<<1, num_block>>>(gpu_st, gpu_rk, 16/num_block);
	cudaMemcpy(state, gpu_st, sizeof(unsigned char)*16, cudaMemcpyDeviceToHost);

	cudaFree(gpu_st);  
	cudaFree(gpu_rk);  
}

/* Perform substitution to each of the 16 bytes
 * Uses S-box as lookup table 
 */
void SubBytes(unsigned char * state) {
	unsigned char *gpu_st, *gpu_sb;
	cudaMalloc((void**)&gpu_st, sizeof(unsigned char)*16); 
	cudaMalloc((void**)&gpu_sb, sizeof(unsigned char)*256);

	cudaMemcpy(gpu_st, state, sizeof(unsigned char)*16, cudaMemcpyHostToDevice);
	cudaMemcpy(gpu_sb, s, sizeof(unsigned char)*256, cudaMemcpyHostToDevice);
	Subbyt<<<1, num_block>>>(gpu_st, gpu_sb, 16/num_block);
	cudaMemcpy(state, gpu_st, sizeof(unsigned char)*16, cudaMemcpyDeviceToHost);

	cudaFree(gpu_st);
	cudaFree(gpu_sb);
}

// Shift left, adds diffusion
void ShiftRows(unsigned char * state) {
	unsigned char tmp2[16];
	unsigned char *gpu_st, *gpu_tp;
	cudaMalloc((void**)&gpu_st, sizeof(unsigned char)*16); 
	cudaMalloc((void**)&gpu_tp, sizeof(unsigned char)*16);

	cudaMemcpy(gpu_st, state, sizeof(unsigned char)*16, cudaMemcpyHostToDevice);
	cudaMemcpy(gpu_tp, tmp2, sizeof(unsigned char)*16, cudaMemcpyHostToDevice);
	ShiftRw<<<1, num_block>>>(gpu_st, gpu_tp, 16/num_block);
	cudaMemcpy(state, gpu_tp, sizeof(unsigned char)*16, cudaMemcpyDeviceToHost);

	cudaFree(gpu_st);
	cudaFree(gpu_tp);
}

 /* MixColumns uses mul2, mul3 look-up tables
  * Source of diffusion
  */
void MixColumns(unsigned char * state) {
	unsigned char tmp2[16];
	unsigned char *gpu_st, *gpu_tp, *gpuml2, *gpuml3;
	cudaMalloc((void**)&gpu_st, sizeof(unsigned char)*16); 
	cudaMalloc((void**)&gpu_tp, sizeof(unsigned char)*16);
	cudaMalloc((void**)&gpuml2, sizeof(unsigned char)*256); 
	cudaMalloc((void**)&gpuml3, sizeof(unsigned char)*256);

	cudaMemcpy(gpu_st, state, sizeof(unsigned char)*16, cudaMemcpyHostToDevice);
	cudaMemcpy(gpu_tp, tmp2, sizeof(unsigned char)*16, cudaMemcpyHostToDevice);
	cudaMemcpy(gpuml2, mul2, sizeof(unsigned char)*256, cudaMemcpyHostToDevice);
	cudaMemcpy(gpuml3, mul3, sizeof(unsigned char)*256, cudaMemcpyHostToDevice);
	Mixcol<<<1, num_block>>>(gpu_tp, gpu_st, gpuml2, gpuml3, 16/num_block);
	cudaMemcpy(state, gpu_tp, sizeof(unsigned char)*16, cudaMemcpyDeviceToHost);

	cudaFree(gpu_st);
	cudaFree(gpu_tp);
	cudaFree(gpuml2);
	cudaFree(gpuml3);
}

/* Each round operates on 128 bits at a time
 * The number of rounds is defined in AESEncrypt()
 */
void Round(unsigned char * state, unsigned char * key) {
	SubBytes(state);
	ShiftRows(state);
	MixColumns(state);
	AddRoundKey(state, key);
}

 // Same as Round() except it doesn't mix columns
void FinalRound(unsigned char * state, unsigned char * key) {
	SubBytes(state);
	ShiftRows(state);
	AddRoundKey(state, key);
}

/* The AES encryption function
 * Organizes the confusion and diffusion steps into one function
 */
void AESEncrypt(unsigned char * message, unsigned char * expandedKey, unsigned char * encryptedMessage) {
	unsigned char state[16]; // Stores the first 16 bytes of original message

	for (int i = 0; i < 16; i++) {
		state[i] = message[i];
	}

	int numberOfRounds = 9;

	AddRoundKey(state, expandedKey); // Initial round

	for (int i = 0; i < numberOfRounds; i++) {
		Round(state, expandedKey + (16 * (i+1)));
	}

	FinalRound(state, expandedKey + 160);

	// Copy encrypted state to buffer
	for (int i = 0; i < 16; i++) {
		encryptedMessage[i] = state[i];
	}
}

int main() {
	cout << "=============================" << endl;
	cout << " 128-bit AES Encryption Tool   " << endl;
	cout << "=============================" << endl;

	char message[100000];

	for(int i=0; i< 100000; i++){
		message[i] = 'h';
	}
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
			paddedMessage[i] = 'h';
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