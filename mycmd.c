#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <time.h>

#include "sha256.h"

#define FIFO_FILE_NAME "myfifo"
#define MAX_PATH 256
#define INPUT_LEN 276
#define ARG_LEN 256
#define CMD_LEN 20
//#define GENERATE_SHA_KEY
//#define DEBUG


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

int CheckPasswordHash(char username[31], char pass[31])
{
    char sha1[SHA256_BLOCK_SIZE+1];
    SHA256_CTX ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, pass, strlen(pass));
    sha256_final(&ctx, sha1);
    sha1[SHA256_BLOCK_SIZE] = '\0';

#ifdef GENERATE_SHA_KEY
    //FILE* fpc = fopen("accounts.config", "w");
    //fclose(fpc);
    FILE* fp_generator = fopen("accounts.config", "a");
    fprintf(fp_generator, "%s %s\n", username, sha1);
    fclose(fp_generator);
#endif

    FILE* fp = fopen("accounts.config", "rb");
    char sha2[SHA256_BLOCK_SIZE+1], user[31];

    while(fscanf(fp, "%s %s", &user, &sha2) != EOF){
        sha2[SHA256_BLOCK_SIZE] = '\0';

    #ifdef DEBUG
        printf("[DEBUG] usr@keyboard: %s\n", username);
        printf("[DEBUG] usr@file    : %s\n", user);
        printf("[DEBUG] SHA@keyboard: %s\n", GetHexSHA(sha1));
        printf("[DEBUG] SHA@file    : %s\n", GetHexSHA(sha2));
    #endif
        if(!strcmp(username, user))
            return memcmp(sha1, sha2, SHA256_BLOCK_SIZE);
    }
    return -1;
}

void LogIn()
{
    char user[31], pass[31];
    char username[31], password[31];

    int login_pipe[2], login_pipe_ret[2];

    printf("Introdu username: ");
    fgets(username, 30, stdin);
    ( (char*) strchr(username, '\n') )[0] = '\0';

    printf("Introdu parola  : ");
    fgets(password, 30, stdin);
    ( (char*) strchr(password, '\n') )[0] = '\0';
    
    if(pipe(login_pipe) == -1){
        fprintf(stderr, "[ERROR] pipe login.\n");
        exit(1);    
    }
    if(pipe(login_pipe_ret) == -1){
        fprintf(stderr, "[ERROR] pipe login feedback.\n");
        exit(1);    
    }

    switch(fork()){
        case -1:
            fprintf(stderr, "[ERROR] Fork 1.\n");
            exit(1);
        case 0:
            close(login_pipe[1]);
            close(login_pipe_ret[0]);
            read(login_pipe[0], &user, 31);
            read(login_pipe[0], &pass, 31);
            int result = CheckPasswordHash(username, pass);
            write(login_pipe_ret[1], &result, 4);
            exit(0);
        default:
            close(login_pipe[0]);
            close(login_pipe_ret[1]);
            write(login_pipe[1], &username, 31);
            write(login_pipe[1], &password, 31);
            int logging_in_status;
            read(login_pipe_ret[0], &logging_in_status, 4);
            if(logging_in_status != 0){
                fprintf(stderr, "[ERROR] Parola gresita.\n");
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

char* GetFilePermissions(int mask)
{
    char* info = malloc(30);
    sprintf(info, "%s", "USR[");
    sprintf(info, "%s%s", info, (mask & S_IRUSR) ? "r" : "-");
    sprintf(info, "%s%s", info, (mask & S_IWUSR) ? "w" : "-");
    sprintf(info, "%s%s", info, (mask & S_IXUSR) ? "x" : "-");
    sprintf(info, "%s%s", info, "]");
    sprintf(info, "%s%s", info, " GRP[");
    sprintf(info, "%s%s", info, (mask & S_IRGRP) ? "r" : "-");
    sprintf(info, "%s%s", info, (mask & S_IWGRP) ? "w" : "-");
    sprintf(info, "%s%s", info, (mask & S_IXGRP) ? "x" : "-");
    sprintf(info, "%s%s", info, "]");
    sprintf(info, "%s%s", info, " OTH[");
    sprintf(info, "%s%s", info, (mask & S_IROTH) ? "r" : "-");
    sprintf(info, "%s%s", info, (mask & S_IWOTH) ? "w" : "-");
    sprintf(info, "%s%s", info, (mask & S_IXOTH) ? "x" : "-");
    sprintf(info, "%s%s", info, "]");
    return info;
}

void PrintFileDetails(char* filepath)
{
    int socket_pair[2];
    char msg[1024];

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, socket_pair) < 0) 
    { 
        fprintf(stderr, "[ERROR] socketpair\n"); 
        exit(1); 
    }

    switch(fork())
    {
        case -1:
            fprintf(stderr, "[ERROR] fork - socket_pair\n");
            exit(1);
        case 0: {
            if(read(socket_pair[0], filepath, MAX_PATH) < 0)
                fprintf(stderr, "[ERROR] Could not read from socket_pair\n");

            struct stat t_stat;
            stat(filepath, &t_stat);
            char* attribs = GetFilePermissions(t_stat.st_mode);

            if(write(socket_pair[0], ctime(&t_stat.st_ctime), 25) == -1){
                fprintf(stderr, "[ERROR] Nu s-a putut scrie in socket_pair 1.\n");
                exit(1);
            }
            if(write(socket_pair[0], ctime(&t_stat.st_mtime), 25) == -1){
                fprintf(stderr, "[ERROR] Nu s-a putut scrie in socket_pair 2.\n");
                exit(1);
            }
            if(write(socket_pair[0], &t_stat.st_size, 8) == -1){
                fprintf(stderr, "[ERROR] Nu s-a putut scrie in socket_pair 3.\n");
                exit(1);
            }
            if(write(socket_pair[0], attribs, 30) == -1){
                fprintf(stderr, "[ERROR] Nu s-a putut scrie in socket_pair 4.\n");
                exit(1);
            }

            exit(0);
        }
        default: {
            write(socket_pair[1], filepath, MAX_PATH);
            char date[30], stats[30];
            unsigned long long file_size;

            printf("\nGasit: \"%s\"\n", filepath);

            if(read(socket_pair[1], date, 25) == -1){
                fprintf(stderr, "[ERROR] Eroare la citirea din socket_pair 1.\n");
                exit(1);
            }
            date[24] = '\0';
            printf("Data crearii       : %s\n", date);

            if(read(socket_pair[1], date, 25) == -1){
                fprintf(stderr, "[ERROR] Eroare la citirea din socket_pair 2.\n");
                exit(1);
            }
            date[24] = '\0';
            printf("Data modificarii   : %s\n", date);

            if(read(socket_pair[1], &file_size, 8) == -1){
                fprintf(stderr, "[ERROR] Eroare la citirea din socket_pair 3.\n");
                exit(1);
            }
            printf("Dimensiune in bytes: %llu\n", file_size);

            if(read(socket_pair[1], stats, 30) == -1){
                fprintf(stderr, "[ERROR] Eroare la citirea din socket_pair 4.\n");
                exit(1);
            }
            printf("Permisiuni fisier  : %s\n", stats);
        }
    }
}

void FindFile(char* path, char *to_find)
{
    DIR *p_dir;
    struct dirent *p_dirent;
    struct stat *p_stat = (struct stat*) malloc(sizeof(struct stat));

    p_dir = opendir(path);
    if(p_dir == NULL){
        fprintf(stderr, "[ERROR] Nu am acces la \"%s\"\n", path);
        return;
    }

    while(1){
        p_dirent = readdir(p_dir);
        if (p_dirent == NULL)
            return;
        if(!strcmp(p_dirent->d_name,".") ||
           !strcmp(p_dirent->d_name,".."))
            continue;

        char next_path[MAX_PATH];
        strcpy(next_path, path);
        strcat(next_path, p_dirent->d_name);

        stat(next_path, p_stat);
        char* fname = p_dirent->d_name;

        switch (p_stat->st_mode & S_IFMT) {
            case S_IFDIR:
                strcat(next_path, "/");
                FindFile(next_path, to_find);
                break;           
            default:
                if(!strcmp(to_find, fname)){
                    PrintFileDetails(next_path);
                }
        }
    }
    closedir(p_dir);
}

void GetFileAttributes(char *filename)
{
    mknod(FIFO_FILE_NAME, S_IFIFO | 0700, 0);
    switch(fork()){
        case -1:
            fprintf(stderr, "[ERROR] GetFileAttributes fork.\n");
            exit(1);
        case 0: {
            int fd = open(FIFO_FILE_NAME, O_WRONLY);
            struct stat sb;
            char filetype[30], date[30];

            if(stat(filename, &sb) == -1){
                fprintf(stderr, "[ERROR] GetFileAttributes - stat.\n");
                exit(1);
            }

            switch (sb.st_mode & S_IFMT) {
                case S_IFBLK:  strcpy(filetype, "block device"); break;
                case S_IFCHR:  strcpy(filetype, "character device"); break;
                case S_IFDIR:  strcpy(filetype, "directory"); break;
                case S_IFIFO:  strcpy(filetype, "FIFO/pipe"); break;
                case S_IFLNK:  strcpy(filetype, "symlink"); break;
                case S_IFREG:  strcpy(filetype, "regular file"); break;
                case S_IFSOCK: strcpy(filetype, "socket"); break;
                default:       strcpy(filetype, "unknown?"); break;
            }

            if(write(fd, &filetype, 30) == -1){
                fprintf(stderr, "[ERROR] Nu s-a putut scrie in fisier fifo 1.\n");
                exit(1);
            }

            if(write(fd, &sb.st_ino, 4) == -1){
                fprintf(stderr, "[ERROR] Nu s-a putut scrie in fisier fifo 2.\n");
                exit(1);
            }

            if(write(fd, &sb.st_mode, 4) == -1){
                fprintf(stderr, "[ERROR] Nu s-a putut scrie in fisier fifo 3.\n");
                exit(1);
            }

            if(write(fd, &sb.st_nlink, 4) == -1){
                fprintf(stderr, "[ERROR] Nu s-a putut scrie in fisier fifo 4.\n");
                exit(1);
            }

            if(write(fd, &sb.st_size, 8) == -1){
                fprintf(stderr, "[ERROR] Nu s-a putut scrie in fisier fifo 5.\n");
                exit(1);
            }

            if(write(fd, ctime(&sb.st_ctime), 24) == -1){
                fprintf(stderr, "[ERROR] Nu s-a putut scrie in fisier fifo 6.\n");
                exit(1);
            }

            if(write(fd, ctime(&sb.st_atime), 24) == -1){
                fprintf(stderr, "[ERROR] Nu s-a putut scrie in fisier fifo 7.\n");
                exit(1);
            }

            if(write(fd, ctime(&sb.st_mtime), 24) == -1){
                fprintf(stderr, "[ERROR] Nu s-a putut scrie in fisier fifo 8.\n");
                exit(1);
            }
            exit(0);
        }
        default: {
            char filetype[30], date[30];
            int inode;
            unsigned int mode, links;
            unsigned long long size;
            int fd = open(FIFO_FILE_NAME, O_RDONLY);

            if(read(fd, filetype, 30) == -1){
                fprintf(stderr, "[ERROR] Nu s-a putut citi <filetype> din fisier fifo.\n");
                exit(1);
            }
            printf("Tip fisier  : %s\n", filetype);

            if(read(fd, &inode, 4) == -1){
                fprintf(stderr, "[ERROR] Nu s-a putut citi <inode> din fisier fifo.\n");
                exit(1);
            }
            printf("Inode fisier: %d\n", inode);

            if(read(fd, &mode, 4) == -1){
                fprintf(stderr, "[ERROR] Nu s-a putut citi <mode> din fisier fifo.\n");
                exit(1);
            }
            printf("Mod fisier  : %lo\n", mode);

            if(read(fd, &links, 4) == -1){
                fprintf(stderr, "[ERROR] Nu s-a putut citi <nlink> din fisier fifo.\n");
                exit(1);
            }
            printf("Links fisier: %lo\n", links);

            if(read(fd, &size, 8) == -1){
                fprintf(stderr, "[ERROR] Nu s-a putut citi <size> din fisier fifo.\n");
                exit(1);
            }
            printf("Size fisier : %llu\n", size);

            if(read(fd, date, 24) == -1){
                fprintf(stderr, "[ERROR] Nu s-a putut citi <cdate> din fisier fifo.\n");
                exit(1);
            }
            date[24] = '\0';
            printf("Data ultima schimbare  : %s\n", date);

            if(read(fd, date, 24) == -1){
                fprintf(stderr, "[ERROR] Nu s-a putut citi <adate> din fisier fifo.\n");
                exit(1);
            }
            date[24] = '\0';
            printf("Data ultimului acces   : %s\n", date);

            if(read(fd, date, 24) == -1){
                fprintf(stderr, "[ERROR] Nu s-a putut citi <mdate> din fisier fifo.\n");
                exit(1);
            }
            date[24] = '\0';
            printf("Data ultimei modificari: %s\n", date);
        }
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
        printf("\n");
        fgets(input, INPUT_LEN, stdin);
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
            if(strlen(arg) == 0)
                fprintf(stderr, "[ERROR] Nume de fisier null.\n");
            else{
                char start_path[MAX_PATH];
                if(getcwd(start_path, sizeof(start_path)) == NULL)
                    fprintf(stderr, "[ERROR] Nu se poate citi directorul curent.\n");
                else{
                    strcat(start_path, "/");
                #ifdef DEBUG
                    printf("[DEBUG] caut \"%s\" in \"%s\"\n", arg, start_path);
                #endif
                    FindFile(start_path, arg);
                }
            }
        }
        else if(!strcmp(command, "mystat")){
            if(access(arg, F_OK) == -1){
                fprintf(stderr, "[ERROR] Fisier inexistent.\n");
            }
            else{
                #ifdef DEBUG
                    printf("[DEBUG] Fiserul \"%s\" exista. Incarc detaliile...\n", arg);
                #endif
                printf("\nStatus fisier \"%s\":\n", arg);
                GetFileAttributes(arg);
            }
        }
    }
}