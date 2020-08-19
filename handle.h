#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <math.h>
#include <stdint.h>
#include "blowfish.h"

#define MAX_NAME_SIZE       32

void init_pwd(char* pwd);
int init_file(int fd_file, uint64_t nb_entries);
int add_pwd(int fd_file, char *name, char *pwd);
int init_db(int fd_file);
void print_names();
char *get_pwd(char *name);
int rm_pwd(char *name, int fd_file);
int is_in_base(char *name);
void change_encryption(int fd_file, char *new_pwd);