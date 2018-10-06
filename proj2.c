#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <openssl/bn.h>
#include <openssl/hmac.h>
#include <stdint.h>
#include <byteswap.h>

#define RUN  0
#define TEST  1
#define DEBUG 0
#define X 30 //timestep value used in run mode

/////////////////////
// This code based off TOTP RFC 6238 implementation
// https://tools.ietf.org/html/rfc6238
/////////////////////

//helper function to print binary representation, got from https://stackoverflow.com/questions/111928/is-there-a-printf-converter-to-print-in-binary-format
void printBits(size_t const size, void const * const ptr)
{
    unsigned char *b = (unsigned char*) ptr;
    unsigned char byte;
    int i, j;

    for (i=size-1;i>=0;i--)
    {
        for (j=7;j>=0;j--)
        {
            byte = (b[i] >> j) & 1;
            printf("%u", byte);
        }
    }
    puts("");
}


int64_t compute_totp(int64_t* currentTime, unsigned char* seedValue){
	//64 byte hash is the output for sha512
	unsigned char hash[64];
	int hashLen;
	if(DEBUG)
		printf("Origin. time: %016llx\n",*currentTime);
	//Reverse bit order of currentTime so that it works with HMAC
	int64_t bigTime = bswap_64(*currentTime);
	if(DEBUG)
		printf("Swapped time: %016llx\n", bigTime);
	// compute the MAC
	if(DEBUG)
	{
		printf("Seed Value %s, length: %d\n", seedValue, strlen(seedValue));
		printf("Message Value %llx, length: %d\n", bigTime, sizeof(bigTime));
	}

	//HMAC function returns hash length and hash
	HMAC(EVP_sha512(), seedValue, strlen(seedValue), (char *)&bigTime, 8, hash, &hashLen);

	if(DEBUG)
	{
		printf("\nSize of hash: %d\nHash: ", hashLen);
		for(int i = 0; i < hashLen; i++)
			printf("%u",hash[i]);
		printf("\n");
	}

	// compute the offset - 
	int offset = hash[hashLen - 1] & 0xf;
	
	int binary =
		(((hash[offset] & 0x7f) << 24) |
		((hash[offset + 1] & 0xff) << 16) |
		((hash[offset + 2] & 0xff) << 8) |
		(hash[offset + 3] & 0xff));

	if(DEBUG)
		printf("Binary: %d\n", binary);

	// perfrom modulus
	int OTP = binary % 100000000;
	if(DEBUG)
		printf("TOTP: %d\n", OTP);

	return OTP; 
}

int32_t main (int argc, char *argv[])
{
	int8_t argsok = 0; 
	int8_t mode=0;
	//64bit because we need 8 byte data for HMAC function
	int64_t t_int;
	//this is the seed that we will be passing into our compute_totp function
	unsigned char seed[] = "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34";

	if (argc > 1){
		if(strncmp(argv[1], "run", 3)==0){
			mode = RUN; 
			argsok=1;
		}
		else if (strncmp(argv[1], "test", 4)==0){
			argsok=1;
			mode = TEST; 
		}
	}
	if(!argsok){
		perror("'./totp test' or './totp run'\n");
		exit(1);
	}
	if (mode == RUN){

		//compute time segment based on current time/period and divide by x (30 in this case)
		time(&t_int);
		t_int = t_int / X;
		printf("Time: %016llx, OTP: %d\n", t_int, compute_totp(&t_int, seed));
	}
	else{
		printf("************************************************************\n\n");
		t_int = 0x0000000000000001;
		printf("Time: %016llx, OTP: %d\n\n", t_int, compute_totp(&t_int, seed));
		printf("************************************************************\n\n");
		t_int = 0x00000000023523EC; 
		printf("Time: %016llx, OTP: %d\n\n", t_int, compute_totp(&t_int, seed));
		printf("************************************************************\n\n");
		t_int = 0x00000000023523ED;
		printf("Time: %016llx, OTP: %d\n\n", t_int, compute_totp(&t_int, seed));
		printf("************************************************************\n\n");
		t_int = 0x000000000273EF07;
		printf("Time: %016llx, OTP: %d\n\n", t_int, compute_totp(&t_int, seed));
		printf("************************************************************\n\n");
		t_int = 0x0000000003F940AA;
		printf("Time: %016llx, OTP: %d\n\n", t_int, compute_totp(&t_int, seed));
		printf("************************************************************\n\n");
		t_int = 0x0000000027BC86AA;
		printf("Time: %016llx, OTP: %d\n\n", t_int, compute_totp(&t_int, seed));
		printf("************************************************************\n\n");
	}

	return 0;
}
