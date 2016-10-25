#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>

void PrintHelp()
{
	printf("login         - pentru logarea in aplicatie\n");
	printf("myfind <file> - cautare fisier recursiv\n")
	printf("mystat <file> - afiseaza atribute fisiier\n");
	printf("quit          - inchide aplicatia\n");
}

int main(int argc, char** argv)
{
	
}