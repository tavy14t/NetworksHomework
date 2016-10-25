#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include "sha256.h"

//#define GENERATE_SHA_KEY

void PrintHelp()
{
	printf("login         - pentru logarea in aplicatie\n");
	printf("myfind <file> - cautare fisier recursiv\n");
	printf("mystat <file> - afiseaza atribute fisiier\n");
	printf("quit          - inchide aplicatia\n");
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

	return memcmp(sha1, sha2, SHA256_BLOCK_SIZE);
}

void LogIn()
{
	char pass[31], newpass[31];
	int login_pipe[2], login_pipe_ret[2];

	printf("Introdu parola: ");
	scanf("%30s[^\n]", &pass);
	
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


int main(int argc, char** argv)
{
	LogIn();
	printf("E bine!");
}