#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <ctype.h>
#include "sha256.h"

#define INPUT_LEN 276
#define ARG_LEN 256
#define CMD_LEN 20
//#define GENERATE_SHA_KEY
#define DEBUG

void PrintHelp()
{
	printf("login         - pentru logarea in aplicatie\n");
	printf("myfind <file> - cautare fisier recursiv\n");
	printf("mystat <file> - afiseaza atribute fisiier\n");
	printf("quit / exit   - inchide aplicatia\n");
}

char* GetHexSHA(char* sha)
{
	char *hex_buffer = (char*) calloc(65, 0);
	for (int i=0; i<SHA256_BLOCK_SIZE; i++)
		sprintf(hex_buffer, "%s%02X", hex_buffer, sha[i] & 0xff);
	return hex_buffer;
}

int CheckPasswordHash(char pass[31])
{
	char sha1[SHA256_BLOCK_SIZE+1];
	SHA256_CTX ctx;

	sha256_init(&ctx);
	sha256_update(&ctx, pass, strlen(pass));
	sha256_final(&ctx, sha1);
	sha1[SHA256_BLOCK_SIZE] = '\0';

#ifdef GENERATE_SHA_KEY
	FILE* fp_generator = fopen("password_hash", "wb");
	fprintf(fp_generator, "%s", sha1);
	fclose(fp_generator);
#endif

	FILE* fp = fopen("password_hash", "rb");
	char sha2[SHA256_BLOCK_SIZE+1];
	fscanf(fp, "%s", &sha2);
	sha2[SHA256_BLOCK_SIZE] = '\0';

#ifdef DEBUG
	printf("[DEBUG] SHA@keyboard: %s\n", GetHexSHA(sha1));
	printf("[DEBUG] SHA@file    : %s\n", GetHexSHA(sha2));
#endif

	return memcmp(sha1, sha2, SHA256_BLOCK_SIZE);
}

void LogIn()
{
	char pass[31], newpass[31];
	int login_pipe[2], login_pipe_ret[2];

	printf("Introdu parola: ");
	fgets(pass, 30, stdin);
	( (char*) strchr(pass, '\n') )[0] = '\0';
	
	if(pipe(login_pipe) == -1){
		fprintf(stderr, "Eroare la pipe-ul de login.\n");
		exit(1);	
	}
	if(pipe(login_pipe_ret) == -1){
		fprintf(stderr, "Eroare la pipe-ul de login feedback.\n");
		exit(1);	
	}

	switch(fork()){
		case -1:
			fprintf(stderr, "Eroare la fork 1.\n");
			exit(1);
		case 0:
			close(login_pipe[1]);
			close(login_pipe_ret[0]);
			read(login_pipe[0], &newpass, 31);
			int result = CheckPasswordHash(newpass);
			write(login_pipe_ret[1], &result, 4);
			exit(0);
		default:
			close(login_pipe[0]);
			close(login_pipe_ret[1]);
			write(login_pipe[1], &pass, strlen(pass) + 1);
			int logging_in_status;
			read(login_pipe_ret[0], &logging_in_status, 4);
			while(logging_in_status != 0){
				fprintf(stderr, "Eroare la logare! Parola gresita.\n");
				exit(1);
			}
	}
}

void ParseString(char* input, char *name, char *arg1)
{
	char input_copy[INPUT_LEN];

	memset(name, 0, CMD_LEN);
	memset(arg1, 0, ARG_LEN);
	memset(input_copy, 0, INPUT_LEN);

	strncpy(input_copy, input, strlen(input));

	int index = 0;
	int input_copyLen = strlen(input_copy);
	while (input_copy[index] == ' ') index++;
	for (int i = 0; i < input_copyLen - index; i++)
		input_copy[i] = input_copy[i + index];
	input_copy[input_copyLen - index] = '\0';

	input_copyLen = strlen(input_copy);
	for (int i = 0; i <= input_copyLen; i++)
		if (input_copy[i] == ' ' || input_copy[i] == '\0')
		{
			strncpy(name, input_copy, i);
			index = i;
			name[i] = '\0';
			break;
		}

	if (input_copy[index + 1] == '"')
	{
		index += 2;
		int startIndex = index;
		while (input_copy[index] != '"')
			index++;

		for (int i = startIndex; i < index; i++)
			arg1[i - startIndex] = input_copy[i];
		arg1[index - startIndex] = '\0';
		index++;
	}
	else if (input_copy[index] == ' ')
	{
		int startIndex = index + 1;
		index++;
		while (input_copy[index] != ' ' && input_copy[index] != '\0') index++;

		for (int i = startIndex; i < index; i++)
			arg1[i - startIndex] = input_copy[i];
		arg1[index - startIndex] = '\0';
	}
}

int main(int argc, char** argv)
{
	char input[INPUT_LEN];
	char command[CMD_LEN];
	char arg[ARG_LEN];
	
	LogIn();

	while(1)
	{
		fgets(input, 276, stdin);
		( (char*) strchr(input, '\n') )[0] = '\0';

		ParseString(input, command, arg);

#ifdef DEBUG
		printf("[DEBUG] input   : %s\n", input);
		printf("[DEBUG] command : %s\n", command);
		printf("[DEBUG] argument: %s\n", arg);
#endif

		if(!strcmp(command, "help"))
			PrintHelp();
		else if(!strcmp(command, "quit") || !strcmp(command, "exit"))
			exit(0);
		else if(!strcmp(command, "login"))
			LogIn();
		else if(!strcmp(command, "myfind")){
	
		}
		else if(!strcmp(command, "mystat")){

		}
	}
}