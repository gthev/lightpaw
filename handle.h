#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <math.h>
#include <stdint.h>
#include <time.h>
#include "blowfish.h"

#define MAX_NAME_SIZE       32

#define MUST_LOWER          (1<<0)
#define MUST_UPPER          (1<<1)
#define MUST_SPECIAL        (1<<2)
#define MUST_NUMBER         (1<<3)

#define IS_LOWER(cons)      !!(cons & MUST_LOWER)
#define IS_UPPER(cons)      !!(cons & MUST_UPPER)
#define IS_SPECIAL(cons)    !!(cons & MUST_SPECIAL)
#define IS_NUMBER(cons)     !!(cons & MUST_NUMBER)

struct gen_pwd_args {
    unsigned int        size_min;
    unsigned int        size_max;
    int                 constraints;
};

void init_pwd(char* pwd);
int init_file(int fd_file, uint64_t nb_entries);
int add_pwd(int fd_file, char *name, char *pwd);
int init_db(int fd_file);
void print_names();
char *get_pwd(char *name);
int rm_pwd(char *name, int fd_file);
int is_in_base(char *name);
void change_encryption(int fd_file, char *new_pwd);
int check_pwd(char* pwd, struct gen_pwd_args *args);
char* gen_pwd(struct gen_pwd_args *args);