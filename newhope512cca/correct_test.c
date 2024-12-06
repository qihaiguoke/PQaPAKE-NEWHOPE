
//
//  PQCgenKAT_kem.c
//
//  Created by Bassham, Lawrence E (Fed) on 8/29/17.
//  Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
//
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "rng.h"
#include "api.h"

#define TEST_ROUNDS 10 // 2^18

#define FIND_FAILURE 1
#define STOP_ON_FAIL 10

#define	MAX_MARKER_LEN		50
#define KAT_SUCCESS          0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR      -3
#define KAT_CRYPTO_FAILURE  -4

int		FindMarker(FILE *infile, const char *marker);
int		ReadHex(FILE *infile, unsigned char *A, int Length, char *str);
void	fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long L);

int
main()
{
    char                fn_rsp[32];
    FILE                *fp_rsp;
    unsigned char       seed[96] = {
        0x60,0x23,0x6A,0x23,0x5B,0x9E,0xCD,0xA3,0x85,0x1B,0xD2,0xFF,
        0xC0,0x6B,0x95,0xCF,0xC2,0x96,0x13,0xC7,0xA3,0x7A,0x15,0x58,
        0x87,0x57,0x01,0x53,0xAF,0x9C,0xFA,0x05,0x0A,0x7B,0xB3,0x17,
        0xD2,0xDF,0x8E,0x44,0xEC,0xC4,0x59,0xAE,0x80,0x95,0x7D,0xBE
    };
    unsigned char       entropy_input[96];
    unsigned char       ct[CRYPTO_CIPHERTEXTBYTES], ss[CRYPTO_BYTES], ss1[CRYPTO_BYTES];
    uint64_t            fail, success;
    uint64_t            ctr;
    #ifdef CPA_TEST
    unsigned char       pk[CRYPTO_PUBLICKEYBYTES], sk[INDCPA_SECRETKEYBYTES];
    #else
    unsigned char       pk[CRYPTO_PUBLICKEYBYTES], sk[NEWHOPE_CCAKEM_SECRETKEYBYTES];
    #endif
    int                 ret_val;
    
    // Create the REQUEST file
    sprintf(fn_rsp, "PQCkemKAT_%d.rsp", CRYPTO_SECRETKEYBYTES);
    if ( (fp_rsp = fopen(fn_rsp, "w")) == NULL ) {
        printf("Couldn't open <%s> for write\n", fn_rsp);
        return KAT_FILE_OPEN_ERROR;
    }
    
    for (int i=0; i<48; i++)
        entropy_input[i] = i;

    randombytes_init(entropy_input, NULL, 256);
    
    fprintf(fp_rsp, "# %s\n\n", CRYPTO_ALGNAME);
    fail = 0;
    ctr = 0;
#if (FIND_FAILURE == 1)	
	printf("%s find Failure start..\n", CRYPTO_ALGNAME);
#else
    printf("%s find Success start..\n", CRYPTO_ALGNAME);
#endif
    while(ctr < TEST_ROUNDS) {
        ctr++;
        randombytes(seed, 48);

        randombytes_init(seed, NULL, 256);
        
        // Generate the public/private keypair
        if ( (ret_val = crypto_kem_keypair(pk, sk)) != 0) {
            printf("crypto_kem_keypair returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
        }

        if ( (ret_val = crypto_kem_enc(ct, ss, pk)) != 0) {
            printf("crypto_kem_enc returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
        }
        
        if ( (ret_val = crypto_kem_dec(ss1, ct, sk)) != 0) {
            printf("crypto_kem_dec returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
        }
#if (FIND_FAILURE == 1)  
        if ( memcmp(ss, ss1, CRYPTO_BYTES) ) {
            fail++;
#ifdef STOP_ON_FAIL
			//fprintf(fp_rsp, "crypto_kem_dec returned bad 'ss' value\n");
            fprintf(fp_rsp, "count = %lu\n", ctr);
            fprintBstr(fp_rsp, "seed = ", seed, 48);
            fprintBstr(fp_rsp, "pk = ", pk, CRYPTO_PUBLICKEYBYTES);
#ifdef CPA_TEST
            fprintBstr(fp_rsp, "sk = ", sk, INDCPA_SECRETKEYBYTES);
#else
            fprintBstr(fp_rsp, "sk = ", sk, CRYPTO_SECRETKEYBYTES);
#endif
            fprintBstr(fp_rsp, "ct = ", ct, CRYPTO_CIPHERTEXTBYTES);
            fprintBstr(fp_rsp, "ss = ", ss, CRYPTO_BYTES);
            fprintBstr(fp_rsp, "ss1 = ", ss1, CRYPTO_BYTES);
            printf("crypto_kem_dec returned bad 'ss' value at %lu-th round.\n", ctr);
            if (fail >= STOP_ON_FAIL) {
                break;
            }
#endif
            //return KAT_CRYPTO_FAILURE; // 这都没关文件...
        }
#else
        if (memcmp(ss, ss1, CRYPTO_BYTES) == 0) {
            success++;
            //fprintf(fp_rsp, "crypto_kem_dec returned bad 'ss' value\n");
            fprintf(fp_rsp, "count = %lu\n", ctr);
            fprintBstr(fp_rsp, "seed = ", seed, 48);
            fprintBstr(fp_rsp, "pk = ", pk, CRYPTO_PUBLICKEYBYTES);
            fprintBstr(fp_rsp, "sk = ", sk, CRYPTO_SECRETKEYBYTES);
            fprintBstr(fp_rsp, "ct = ", ct, CRYPTO_CIPHERTEXTBYTES);
            fprintBstr(fp_rsp, "ss = ", ss, CRYPTO_BYTES);
            fprintBstr(fp_rsp, "ss1 = ", ss1, CRYPTO_BYTES);
            printf("crypto_kem_dec returned correct 'ss' value at %lu-th round.\n", ctr);
            if (success > 3) {
                break;
            }
            //return KAT_CRYPTO_FAILURE; // 这都没关文件...
    }
#endif
    }
    printf("Falure times: %ld / in total %ld rounds of Test\n", fail, ctr);
    fclose(fp_rsp);

    return KAT_SUCCESS;
}

//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//
//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//
int
FindMarker(FILE *infile, const char *marker)
{
	char	line[MAX_MARKER_LEN];
	int		i, len;
	int curr_line;

	len = (int)strlen(marker);
	if ( len > MAX_MARKER_LEN-1 )
		len = MAX_MARKER_LEN-1;

	for ( i=0; i<len; i++ )
	  {
	    curr_line = fgetc(infile);
	    line[i] = curr_line;
	    if (curr_line == EOF )
	      return 0;
	  }
	line[len] = '\0';

	while ( 1 ) {
		if ( !strncmp(line, marker, len) )
			return 1;

		for ( i=0; i<len-1; i++ )
			line[i] = line[i+1];
		curr_line = fgetc(infile);
		line[len-1] = curr_line;
		if (curr_line == EOF )
		    return 0;
		line[len] = '\0';
	}

	// shouldn't get here
	return 0;
}

//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//
int
ReadHex(FILE *infile, unsigned char *A, int Length, char *str)
{
	int			i, ch, started;
	unsigned char	ich;

	if ( Length == 0 ) {
		A[0] = 0x00;
		return 1;
	}
	memset(A, 0x00, Length);
	started = 0;
	if ( FindMarker(infile, str) )
		while ( (ch = fgetc(infile)) != EOF ) {
			if ( !isxdigit(ch) ) {
				if ( !started ) {
					if ( ch == '\n' )
						break;
					else
						continue;
				}
				else
					break;
			}
			started = 1;
			if ( (ch >= '0') && (ch <= '9') )
				ich = ch - '0';
			else if ( (ch >= 'A') && (ch <= 'F') )
				ich = ch - 'A' + 10;
			else if ( (ch >= 'a') && (ch <= 'f') )
				ich = ch - 'a' + 10;
            else // shouldn't ever get here
                ich = 0;
			
			for ( i=0; i<Length-1; i++ )
				A[i] = (A[i] << 4) | (A[i+1] >> 4);
			A[Length-1] = (A[Length-1] << 4) | ich;
		}
	else
		return 0;

	return 1;
}

void
fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long L)
{
	unsigned long long  i;

	fprintf(fp, "%s", S);

	for ( i=0; i<L; i++ )
		fprintf(fp, "%02X", A[i]);

	if ( L == 0 )
		fprintf(fp, "00");

	fprintf(fp, "\n");
}

