#include <stdlib.h>
#include <fcntl.h>
#include "handle.h"

char magic[8] = {0x54, 0x12, 0xaf, 0xb3, 0x3c, 0x81, 0xa2, 0x5e};

/* Pour les caractères spéciaux, on utilisera 
@, $, +, ? et !, et on stocke leur caractères ascii ici*/

#define NR_SPECIALS     5
const char specials[NR_SPECIALS] = {0x40, 0x24, 0x2b, 0x3f, 0x21};

//au début du fichier : 8 octets pour le mot magique, 8 octets pour le nb d'entrées
//name doit faire 32 octets (quitte à être rempli de \0 à la fin)
struct db_entry {
    char*            name;
    uint64_t    size_mdp;
    char*           mdp;
    off_t           off_file;
};

static uint64_t nb_entry = -1;

static struct db_entry *pwddb = NULL;

static BLOWFISH_CTX ctx;

//Un block fait 8 octets ! Ne positionne pas le curseur
static int encrypt_write_block(int fd_file, char *block) {
    uint32_t left = *(uint32_t*)block;
    uint32_t right = *(uint32_t*)(block+4);

    Blowfish_Encrypt(&ctx, &left, &right);

    if(write(fd_file, &left, 4) < 4) {
        return 1;
    }
    if(write(fd_file, &right, 4) < 4) {
        return 1;
    }

    return 0;
}

//reads a block, puts it in buffer (must be allocated)
static int read_decrypt_block(int fd_file, char *buffer) {
    uint32_t left;
    uint32_t right;

    if(read(fd_file, &left, 4) < 4) {
        return 1;
    }
    if(read(fd_file, &right, 4) < 4) {
        return 1;
    }

    Blowfish_Decrypt(&ctx, &left, &right);

    memcpy(buffer, &left, 4);
    memcpy(buffer+4, &right, 4);

    return 0;
}

void init_pwd(char* pwd) {
    Blowfish_Init(&ctx, (unsigned char*)pwd, strlen(pwd));
    srand(time(NULL));
}

int init_file(int fd_file, uint64_t nb_entries) {
    //on se place au début du fichier
    lseek(fd_file, 0, SEEK_SET);

    encrypt_write_block(fd_file, magic);

    encrypt_write_block(fd_file, (char*)&nb_entries);

    nb_entry = nb_entries;

    return 0;
}

int add_pwd(int fd_file, char *name, char *pwd) {
    if(nb_entry < 0) return -1;
    
    //on recherche si le nom existe déjà...
    if(pwddb) {
        for(int i=0; i<nb_entry; i++) {
            if(strcmp(name, pwddb[i].name) == 0) return 1;
        }
    }


    nb_entry++;
    
    uint64_t size_pwd = strlen(pwd);

    //juste pour être sûr...
    for(int i=strlen(name); i<MAX_NAME_SIZE; i++) {
        name[i] = '\0';
    }

    if(!pwddb) {
        pwddb = (struct db_entry *)calloc(nb_entry, sizeof(struct db_entry));
    } else {
        pwddb = (struct db_entry *)realloc(pwddb , nb_entry * sizeof(struct db_entry));
    }

    struct db_entry *last_entry = &pwddb[nb_entry - 1];

    last_entry->name = name;
    last_entry->mdp = pwd;
    last_entry->size_mdp = size_pwd;

    //printf("i'monna write %s, %ld, %s, and nb_entry = %ld\n", name, size_pwd, pwd, nb_entry);

    lseek(fd_file, 8, SEEK_SET);

    encrypt_write_block(fd_file, (char*)&nb_entry);

    lseek(fd_file, 0, SEEK_END);

    last_entry->off_file = lseek(fd_file, 0, SEEK_CUR);

    //on écrit le nom
    for(int i=0; i<MAX_NAME_SIZE/8; i++) {
        encrypt_write_block(fd_file, &name[8*i]);
    }

    encrypt_write_block(fd_file, (char*)&size_pwd);

    //ici, il faut bien penser qu'on ne code pas forcément le caractère final \0 ! Il faudra le rajouter, vu qu'on connaîtra la taille du mdp
    char* fin_pwd = pwd+((int)ceil(((double)size_pwd)/8.f))*8; //on fait des manips pour avoir des blocks de 8

    for(char* block = pwd; block < fin_pwd; block+=8) {
        encrypt_write_block(fd_file, block);
    }

    return 0;
}

void print_names() {

    printf("=====================\n");
    printf("Liste des mots de passe enregistrés\n");

    for(int i=0; i<nb_entry; i++) {
        printf(" - %s\n", pwddb[i].name);
    }

    printf("====================\n");
}

char *get_pwd(char *name) {
    char *pwd_copied;
    
    for(int i=0; i<nb_entry; i++) {
        if(strcmp(name, pwddb[i].name) == 0) {
            pwd_copied = (char*)calloc(pwddb[i].size_mdp + 1, sizeof(char)); //Pour le \0...
            memcpy(pwd_copied, pwddb[i].mdp, pwddb[i].size_mdp + 1);
            return pwd_copied;
        }
    }

    return NULL;
}

int init_db(int fd_file) {

    int rc = 0;
    char *name;

    lseek(fd_file, 0, SEEK_SET);

    char *read_magic = (char*)calloc(8, sizeof(char));

    read_decrypt_block(fd_file, read_magic);

    for(int i=0; i<8; i++) {
        if(read_magic[i] != magic[i]) rc = 1;
    }

    if(rc == 1) { printf("Erreur de lecture. Mot de passe erroné ?\n"); return 1; }

    read_decrypt_block(fd_file, (char*)&nb_entry);

    printf("%ld pwds in file\n", nb_entry);

    if(nb_entry < 0) return 1;
    if(nb_entry == 0) return 0;

    pwddb = (struct db_entry*)calloc(nb_entry, sizeof(struct db_entry));

    for(int i=0; i<nb_entry; i++) {
        struct db_entry *entry = &pwddb[i];

        name = (char*)calloc(MAX_NAME_SIZE, sizeof(char));

        entry->off_file = lseek(fd_file, 0, SEEK_CUR);

        //on lit le nom
        for(int j=0; j<MAX_NAME_SIZE/8; j++) {
            read_decrypt_block(fd_file, &name[8*j]);
        }


        entry->name = name;

        //printf("I just read name = 0x%lx\n", *(uint64_t*)name);

        //on lit la taille du mdp
        read_decrypt_block(fd_file, (char*)&entry->size_mdp);

        //printf("mdp of size %ld\n", entry->size_mdp);

        int nb_blocks_mdp = (int)ceil(((double)(entry->size_mdp+1))/8.f);

        //et le mdp
        entry->mdp = (char*)calloc(8*nb_blocks_mdp, sizeof(char));

        for(int j=0; j<nb_blocks_mdp; j++) {
            read_decrypt_block(fd_file, &entry->mdp[8*j]);
        }

        //on complète avec des \0
        for(int j=entry->size_mdp; j<8*nb_blocks_mdp; j++) {
            entry->mdp[j] = '\0';
        }

        //printf("mdp is %s\n", entry->mdp);
    }

    return 0;
}

int rm_pwd(char* name, int fd_file) {

    struct db_entry *entry = NULL;
    int idx_orig = 0, idx = 0;
    int curseur_end = lseek(fd_file, 0, SEEK_END);

    for(int i=0; i<nb_entry; i++) {
        if(strcmp(pwddb[i].name, name) == 0) {
            entry = &pwddb[i];
            idx_orig = i;
        }
    }

    if(!entry) return 1;

    lseek(fd_file, entry->off_file, SEEK_SET);

    idx = idx_orig;

    //d'abord, recopier dans le fichier, en modifiant les off_file
    if(idx < nb_entry - 1) {

        int p1 = entry->off_file, p2, p3;

        while(idx < nb_entry - 1) {

            p2 = pwddb[idx+1].off_file;
            p3 = (idx < nb_entry - 2)? pwddb[idx+2].off_file : curseur_end;

            char *buf = (char*)calloc(p3-p2, sizeof(char));

            lseek(fd_file, p2, SEEK_SET);

            if((p3-p2) % 8 != 0) printf("/!\\ problème\np3 = %d et p2 = %d\n", p3, p2);

            for(int i=0; i<(p3-p2)/8; i++) {
                read_decrypt_block(fd_file, &buf[8*i]);
            }

            lseek(fd_file, p1, SEEK_SET);

            pwddb[idx+1].off_file = p1;

            for(int i=0; i<(p3-p2)/8; i++) {
                encrypt_write_block(fd_file, &buf[8*i]);
            }

            free(buf);
            idx++;

            p1 = lseek(fd_file, 0, SEEK_CUR);
        }

    }

    //on tronque le fichier
    ftruncate(fd_file, lseek(fd_file, 0, SEEK_CUR));

    //puis, décaler dans la db
    free(entry->name);
    free(entry->mdp);

    for(int i=idx_orig+1; i<nb_entry; i++) {
        memcpy(&pwddb[i-1], &pwddb[i], sizeof(struct db_entry));
        //pwddb[i-1] = pwddb[i];
    }

    nb_entry--;

    pwddb = realloc(pwddb, nb_entry * sizeof(struct db_entry));

    lseek(fd_file, 8, SEEK_SET);
    encrypt_write_block(fd_file, (char*)&nb_entry);

    return 0;
}


int is_in_base(char *name) {
    
    for(int i=0; i<nb_entry; i++) {
        if(strcmp(pwddb[i].name, name) == 0) return 1;
    }

    return 0;
}


void change_encryption(int fd_file, char *new_pwd) {

    int taille_fichier = lseek(fd_file, 0, SEEK_END);
    char *buffer = (char*)calloc(taille_fichier, sizeof(char));

    if(!buffer) {
        perror("Erreur change_encryption, allocation buffer");
        exit(1);
    }

    if(taille_fichier % 8 != 0) {
        printf("/!\\ taille du fichier pas divisible par 8\n");
    }

    lseek(fd_file, 0, SEEK_SET);

    for(int i=0; i<taille_fichier/8; i++) {
        read_decrypt_block(fd_file, &buffer[8*i]);
    }

    init_pwd(new_pwd);

    lseek(fd_file, 0, SEEK_SET);

    for(int i=0; i<taille_fichier/8; i++) {
        encrypt_write_block(fd_file, &buffer[8*i]);
    } 

}

char* gen_pwd(struct gen_pwd_args *args) {

    int sizemdp = args->size_min + (rand() % (args->size_max - args->size_min + 1));

    //printf("min %d max %d size %d\n", args->size_min, args->size_max, sizemdp);

    char *pwd = (char*)calloc(sizemdp + 1, sizeof(char));
    int constraints = args->constraints;

    int total = 2*IS_NUMBER(constraints) + 2*IS_LOWER(constraints) + 2*IS_UPPER(constraints) + IS_SPECIAL(constraints);
    int *choix = (int*)calloc(total, sizeof(int));

    int i=0;
    if(IS_NUMBER(constraints)) {
        choix[i] = 0;
        choix[i+1] = 0;
        i += 2;
    }

    if(IS_LOWER(constraints)) {
        choix[i] = 1;
        choix[i+1] = 1;
        i += 2;
    }

    if(IS_UPPER(constraints)) {
        choix[i] = 2;
        choix[i+1] = 2;
        i += 2;
    }

    if(IS_SPECIAL(constraints)) {
        choix[i] = 3;
        i += 1;
    }

    do {

        for(i=0; i<sizemdp; i++) {
            switch (choix[rand() % total])
            {
            case 0:
                //NUMBER
                pwd[i] = '0' + (rand() % 10);
                break;
            
            case 1:
                //LOWER
                pwd[i] = 'a' + (rand() % 26);
                break;

            case 2:
                //UPPER
                pwd[i] = 'A' + (rand() % 26);
                break;

            case 3:
                //SPECIAL
                pwd[i] = specials[rand() % NR_SPECIALS];
                break;

            default:
                printf("Truc bizarre dans la génération...\n");
                return NULL;
                break;
            }
        }

    } while(!check_pwd(pwd, args));

    return pwd;
}

int check_pwd(char* pwd, struct gen_pwd_args *args) {
    int constraints_read = 0;
    for(int i=0; pwd[i] != '\0'; i++) {
        int c = pwd[i];
        if(c>=0x30 && c<0x3a) constraints_read |= MUST_NUMBER;
        if(c>=0x41 && c<0x5b) constraints_read |= MUST_UPPER;
        if(c>=0x61 && c<0x7b) constraints_read |= MUST_LOWER;
        for(int j=0; j<NR_SPECIALS; j++) { if(c == specials[j]) constraints_read |= MUST_SPECIAL;}
    }

    return constraints_read == args->constraints;
}