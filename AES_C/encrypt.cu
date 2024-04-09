/* encrypt.cpp
 * Performs encryption using AES 128-bit
 * @author Cecelia Wisniewska
 */

#include <iostream>
#include <cstring>
#include <fstream>
#include <sstream>
#include "structures.h"

using namespace std;

int num_block = 16;

/* Serves as the initial round during encryption
 * AddRoundKey is simply an XOR of a 128-bit block with the 128-bit key.
 */
__device__ void AddRoundKey(unsigned char * state,int st, int ed, unsigned char * roundKey) {
	for (int i = st; i < ed; i++) {
		state[i] ^= roundKey[i];
	}
}

/* Perform substitution to each of the 16 bytes
 * Uses S-box as lookup table 
 */
__device__ void SubBytes(unsigned char * state, int st, int ed, unsigned char * sbox) {
	for (int i = st; i < ed; i++) {
		state[i] = sbox[state[i]];
	}
}

// Shift left, adds diffusion
__device__ void ShiftRows(unsigned char * state, int st, int ed) {
	unsigned char tmp[16];

	for (int i=st; i<ed; i++) {
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

	for (int i = st; i < ed; i++) {
		state[i] = tmp[i];
	}
}

 /* MixColumns uses mul2, mul3 look-up tables
  * Source of diffusion
  */
__device__ void MixColumns(unsigned char * sta, int st, int ed, unsigned char * mul2g, unsigned char * mul3g) {
	unsigned char tmp[16];

	for (int i=st; i<ed; i++) {
		if((i%4) == 0) tmp[i] = (unsigned char) mul2g[sta[i]] ^ mul3g[sta[i+1]] ^ sta[i+2] ^ sta[i+3];
		else if((i%4) == 1) tmp[i] = (unsigned char) sta[i-1] ^ mul2g[sta[i]] ^ mul3g[sta[i+1]] ^ sta[i+2];
		else if((i%4) == 2) tmp[i] = (unsigned char) sta[i-2] ^ sta[i-1] ^ mul2g[sta[i]] ^ mul3g[sta[i+1]];
		else if((i%4) == 3) tmp[i] = (unsigned char) mul3g[sta[i-3]] ^ sta[i-2] ^ sta[i-1] ^ mul2g[sta[i]];
	} 

	for (int i = st; i < ed; i++) {
		sta[i] = tmp[i];
	}
}

__global__ void AESCRY(unsigned char *gst, unsigned char *gmul2, unsigned char *gmul3, unsigned char *gsb, unsigned char *gky, int n){
	int st = threadIdx.x*n;
	int ed = st+n;
	int numberOfRounds = 9;
	AddRoundKey(gst,st,ed,gky);
	for (int i = 0; i < numberOfRounds; i++) {
		SubBytes(gst, st, ed, gsb);
		ShiftRows(gst, st, ed);
		MixColumns(gst, st, ed, gmul2, gmul3);
		AddRoundKey(gst, st, ed, gky + (16 * (i+1)));
		
	}
	SubBytes(gst, st, ed, gsb);
	ShiftRows(gst, st, ed);
	AddRoundKey(gst, st, ed, gky+160);
}

/* The AES encryption function
 * Organizes the confusion and diffusion steps into one function
 */
void AESEncrypt(unsigned char * message, unsigned char * expandedKey, unsigned char * encryptedMessage) {
	unsigned char state[16]; // Stores the first 16 bytes of original message
	for (int i = 0; i < 16; i++) {
		state[i] = message[i];
	}
	

	unsigned char *gpu_st, *gpuml2, *gpuml3, *gpu_sb, *gpu_ky;
	cudaMalloc((void**)&gpu_st, sizeof(unsigned char)*16); 
	cudaMalloc((void**)&gpu_ky, sizeof(unsigned char)*176);
	cudaMalloc((void**)&gpuml2, sizeof(unsigned char)*256); 
	cudaMalloc((void**)&gpuml3, sizeof(unsigned char)*256);
	cudaMalloc((void**)&gpu_sb, sizeof(unsigned char)*256);

	cudaMemcpy(gpu_st, state, sizeof(unsigned char)*16, cudaMemcpyHostToDevice);
	cudaMemcpy(gpu_ky, expandedKey, sizeof(unsigned char)*176, cudaMemcpyHostToDevice);
	cudaMemcpy(gpuml2, mul2, sizeof(unsigned char)*256, cudaMemcpyHostToDevice);
	cudaMemcpy(gpuml3, mul3, sizeof(unsigned char)*256, cudaMemcpyHostToDevice);
	cudaMemcpy(gpu_sb, s, sizeof(unsigned char)*256, cudaMemcpyHostToDevice);

	AESCRY<<<1, num_block>>>(gpu_st, gpuml2, gpuml3, gpu_sb, gpu_ky, 16/num_block);

	cudaMemcpy(state, gpu_st, sizeof(unsigned char)*16, cudaMemcpyDeviceToHost);

	cudaFree(gpu_st);  
	cudaFree(gpu_ky);  
	cudaFree(gpu_sb);  
	cudaFree(gpuml2);  
	cudaFree(gpuml3);

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
	for(int i=0;i<100000; i++){
		message[i] = 'h';
	}
	cout << message << endl;

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