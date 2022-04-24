/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

#define RSA_KEY_SIZE 1024
#define MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)
int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	char rsa_text[MAX_PLAIN_LEN_1024] ={0,};
	char rsa_ci[RSA_CIPHER_LEN_1024] ={0,};
	char text[1024] = {0,};
	char ciphertext[1024] = {0,};
	char detext[1024] = {0,};
	int len=1024;
	
	char * opmenu[4] = {"-e","-d","RSA","Ceaser"};
	
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INOUT,
					 TEEC_MEMREF_TEMP_OUTPUT, TEEC_MEMREF_TEMP_INPUT);
	op.params[0].tmpref.buffer = text;
	op.params[0].tmpref.size = len;
	op.params[1].value.a = 1;
	op.params[3].tmpref.buffer = rsa_text;
	op.params[3].tmpref.size = MAX_PLAIN_LEN_1024;
	op.params[2].tmpref.buffer = rsa_ci;
	op.params[2].tmpref.size = RSA_CIPHER_LEN_1024;

	if(argc==4 && strcmp(argv[1], opmenu[0])==0){
		//file make
		//FILE* wfile = fopen(argv[2], "w");
		//fprintf(wfile, "test");
		//fclose(wfile);
		//file check
		FILE* pfile = fopen(argv[2],"r");
		if(pfile == NULL){
			printf("no file");
		}
		fgets(text,len,pfile);
		printf("========================Encryption========================\n");
		
		
		if(strcmp(argv[3],opmenu[2])==0){
			//RSA
			//write memory
			memcpy(rsa_text,text,MAX_PLAIN_LEN_1024);
			memcpy(op.params[3].tmpref.buffer,rsa_text,MAX_PLAIN_LEN_1024);
			//tee invoke to make key
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_RSA_key, &op,
								 &err_origin);
			if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);

			//tee invoke to encrypt
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_RSA, &op,
								 &err_origin);
			if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);
			// read ciphered text
			memcpy(rsa_ci, op.params[2].tmpref.buffer, RSA_CIPHER_LEN_1024);

			
			//encrypted file create
			FILE* encryptedfile = fopen("encrypted.txt","w");
			fprintf(encryptedfile, rsa_ci);
			fclose(encryptedfile);
			printf("encrypted.txt\n");
					
		}else if(strcmp(argv[3],opmenu[3])==0){
			//ceaser al
			//write text to memory
			memcpy(op.params[0].tmpref.buffer,text,len);
			//tee invoke to encrypt
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_Ceaser_en, &op,
								 &err_origin);
			if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);
			//read ciphered text 
			memcpy(ciphertext, op.params[0].tmpref.buffer, len);

		
			//encrypted file create
			FILE* encryptedfile = fopen("encrypted.txt","w");
			fprintf(encryptedfile, ciphertext);
			fclose(encryptedfile);
			//key file create
			FILE* keyfile = fopen("key.txt","w");
			fprintf(keyfile,"%d",op.params[1].value.a);
			fclose(keyfile);
			printf("encrypted.txt + key.txt\n");
		}
		

	}
	else if(argc==4 && strcmp(argv[1],opmenu[1])==0){
		//decrypte
		int key;
		//chipered text file check
		FILE* pfile = fopen(argv[2],"r");
		if(pfile == NULL){
			printf("no file");
		}

		fgets(detext,len,pfile);
		//key file check
		FILE* kfile = fopen(argv[3],"r");
		if(kfile == NULL){
			printf("no file");
		}
		fscanf(kfile,"%d",&key);
		fclose(kfile);
		op.params[1].value.a = key;
		printf("========================Decryption========================\n");
		
		memcpy(op.params[0].tmpref.buffer, detext, len);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_Ceaser_de, &op,
					 &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);
		
		memcpy(detext, op.params[0].tmpref.buffer, len);
		printf("decrypted.txt");
		//file make
		FILE* dfile = fopen("decrypted.txt", "w");
		fprintf(dfile, detext);
		fclose(dfile);
	
	}else{
		printf("please check the command\n");
	}
	
	
	/*
	 * We're done with the TA, close the session and
	 * destroy the context.
	 *
	 * The TA will print "Goodbye!" in the log when the
	 * session is closed.
	 */

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
	
