#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <termios.h>
#include "handle.h"
//#include "blowfish.c"

#define REINIT 1
#define ADDREM 2
#define SEE    3
#define GEN    4
#define CHGMDP 5
#define QUIT   6

#define DATA "lightdata"

#define MDPSIZE 128

void get_password(char *password)
{
    static struct termios old_terminal;
    static struct termios new_terminal;

    tcgetattr(STDIN_FILENO, &old_terminal);

    // do not echo the characters
    new_terminal = old_terminal;
    new_terminal.c_lflag &= ~(ECHO);

    tcsetattr(STDIN_FILENO, TCSANOW, &new_terminal);

    if (fgets(password, MDPSIZE, stdin) == NULL)
        password[0] = '\0';
    else
        password[strlen(password)-1] = '\0';

    tcsetattr(STDIN_FILENO, TCSANOW, &old_terminal);
}

int main() {
    unsigned int choice, rc;
    char* pwd = (char*)calloc(56,sizeof(char));
    int fd_file;
    FILE* data_file;
    int menu = 1;

    fd_file = open(DATA, O_RDWR);

    if(fd_file < 0) {
        int c;
        //perror("debug : ");
        printf("No password data found. Creating one... Password (max 55 chars.) ?\n");
        scanf("%55s", pwd);
        if((c = fgetc(stdin)) != '\n' && c != EOF) {
            //plus de 55 caractères
            printf("max 55 chars ! Do it again\n");
            return 1;
        }

        remove(DATA);

        fd_file = open(DATA, O_RDWR | O_CREAT);

        data_file = fdopen(fd_file, "r+");

        if(fd_file < 0 || !data_file) {
            printf("Problem while creating the file. Exiting...\n");
            remove(DATA);
            return 1;
        }

        chmod(DATA, S_IRUSR | S_IWUSR);

        init_pwd(pwd);
        init_file(fd_file, 0);

    } else {

        printf("Please enter your password:\n");
        get_password(pwd);
        fflush(stdin);

        init_pwd(pwd);

        //décrypter le fichier
        rc = init_db(fd_file);

        if(rc < 0) {
            perror("Erreur de lecture du fichier");
            return 1;
        }
        if(rc > 0) {
            return 1;
        }

    }

    while(menu) {
        printf(" _      _       _     _   _____   __          __\n");
        printf("| |    (_)     | |   | | |  __ \\ /\\ \\        / /\n");
        printf("| |     _  __ _| |__ | |_| |__) /  \\ \\  /\\  / / \n");
        printf("| |    | |/ _` | '_ \\| __|  ___/ /\\ \\ \\/  \\/ /  \n");
        printf("| |____| | (_| | | | | |_| |  / ____ \\  /\\  /   \n");
        printf("|______|_|\\__, |_| |_|\\__|_| /_/    \\_\\/  \\/  \n");
        printf("           __/ |                           \n");
        printf("          |___/                   \n");

        printf("Bienvenue dans LightPAssWord ! Que voulez-vous faire ?\n");
        printf("1. Réinitialiser vos données\n");
        printf("2. Ajouter, enlever ou modifier un mot de passe de la base\n");
        printf("3. Voir un mot de passe\n");
        printf("4. Générer un mot de passe\n");
        printf("5. Changer le mot de passe LightPaw\n");
        printf("6. Quitter\n");
        printf("> ");
        scanf("%u", &choice);

        switch (choice)
        {
        case REINIT:
            printf("Vous allez supprimer tous les mots de passe enregistrés\n");
            printf("Êtes-vous sûr.e de vouloir faire ça ?\n");
            printf("1. Oui\n2. Non\n> ");
            scanf("%u", &choice);
            if(choice == 1) {
                //supprimer le fichier, relancer le gestionnaire
                remove(DATA);
                return 0;
            } else if(choice == 2) {
                break;
            } else {
                printf("Je n'ai pas compris ce que vous avez dit.\n");
                break;
            }
            
            break;

        case ADDREM:
            printf("Voulez-vous : \n1. Ajouter un mot de passe\n2. Enlever un mot de passe\n3. Changer un mot de passe\n4. Retour\n> ");
            scanf("%d", &choice);
            switch (choice)
            {
            case 1:
                printf("Le nom du site (au plus 31 caractères) ?\n> ");
                char *nom_site = (char*)calloc(MAX_NAME_SIZE, sizeof(char));
                scanf("%31s", nom_site);

                //
                int c;
                if((c = fgetc(stdin)) != '\n' && c != EOF) {
                //plus de 55 caractères
                    printf("max 31 chars ! Do it again\n");
                    break;
                }

                char *new_pwd1 = (char*)calloc(MDPSIZE, 1);
                char *new_pwd2 = (char*)calloc(MDPSIZE, 1);

    type_mdp:
                /* new_pwd1 = getpass("Le mot de passe (max 127 caractères) : ");
                new_pwd2 = getpass("Veuillez le confirmer : "); */
                printf("Le mot de passe (max 127 caractères) : ");
                get_password(new_pwd1);
                fflush(stdin);
                printf("\nConfirmation : ");
                get_password(new_pwd2);
                fflush(stdin);
                printf("\n");

                //printf("Debug : %s @@ %s\n", new_pwd1, new_pwd2);

                if(strcmp(new_pwd1, new_pwd2)) {
                    printf("Les mots de passe ne correspondent pas !\n");
                    //getchar();
                    goto type_mdp;
                }

                rc = add_pwd(fd_file, nom_site, new_pwd1);

                free(new_pwd2);

                if(rc < 0) {
                    printf("Erreur dans l'ajout du pwd\n");
                    menu = 0;
                    break;
                }
                if(rc > 0) {
                    printf("Le site est déjà ajouté !\n");
                    break;
                }

                printf("Mot de passe pour %s ajouté !\n", nom_site);

                //getchar();

                break;

            case 2:
                printf("Quel nom ?\n> ");
                char *rm_name = (char*)calloc(32, sizeof(char));
                scanf("%31s", rm_name);

                printf("Êtes-vous sûr.e de vouloir supprimer le mot de passe pour %s ?\n1. Oui\n2. Non\n> ", rm_name);
                scanf("%d", &choice);

                rc = rm_pwd(rm_name, fd_file);

                if(rc > 0) {
                    printf("Mot de passe pour %s non trouvé\n", rm_name);
                    //getchar();
                } else {
                    printf("Mot de passe pour %s supprimé.\n", rm_name);
                    //getchar();
                }


                free(rm_name);

                break;

            case 3:
                printf("Quel nom ?\n> ");
                char *change_name = (char*)calloc(32, sizeof(char));
                scanf("%31s", change_name);

                printf("Êtes-vous sûr.e de vouloir modifier le mot de passe pour %s ?\n1. Oui\n2. Non\n> ", change_name);
                scanf("%d", &choice);

                

                if(!is_in_base(change_name)) {
                    printf(" %s non trouvé\n", change_name);
                    //getchar();
                } else {
                    char *new_pwd1 = (char*)calloc(MDPSIZE, 1);
                    char *new_pwd2 = (char*)calloc(MDPSIZE, 1);

                    int continuer = 1;
                /* new_pwd1 = getpass("Le mot de passe (max 127 caractères) : ");
                new_pwd2 = getpass("Veuillez le confirmer : "); */
                    while(continuer) {
                        
                        int c;
                        while((c = fgetc(stdin)) != '\n' && c != EOF);

                        printf("Le nouveau mot de passe (max 127 caractères) : ");
                        get_password(new_pwd1);
                        fflush(stdin);
                        printf("\nConfirmation : ");
                        get_password(new_pwd2);
                        fflush(stdin);
                        printf("\n");

                        //printf("Debug : %s @@ %s\n", new_pwd1, new_pwd2);

                        if(strcmp(new_pwd1, new_pwd2)) {
                            printf("Les mots de passe ne correspondent pas !\n");
                            //getchar();
                            continue;
                        }

                        continuer = 0;

                        free(new_pwd2);

                    }

                    rc = rm_pwd(change_name, fd_file);

                    add_pwd(fd_file, change_name, new_pwd1);

                    printf("Mot de passe pour %s changé !\n\n", change_name);

                }
                break;

            case 4:
                break;
            
            default:
                printf("Je ne reconnais pas cette option...\n");
                break;
            }
            break;

        case SEE:
    see:
            printf("Vous voulez : \n");
            printf("1. Lister les noms des sites enregistrés\n2. Voir un mot de passe\n3. Retour\n> ");
            scanf("%d", &choice);
            char *req_name = (char*)calloc(32, sizeof(char)), *see_pwd;
            switch (choice)
            {
            case 1:
                print_names();
                goto see;
                break;

            case 2:
                
                printf("Quel nom ?\n> ");
                scanf("%31s", req_name);

                see_pwd = get_pwd(req_name);

                if(!see_pwd) {
                    printf("Aucun mot de passe trouvé pour %s\n", req_name);
                    goto see;
                } else {
                    printf("Mot de passe pour %s : %s\n", req_name, see_pwd);
                }

                free(req_name);
                //getchar();
                break;

            case 3:
                break;
            
            default:
                printf("Je ne reconnais pas cette option...\n");
                break;
            }
            break;

        case GEN:
            printf("Not yet implemented\n");
            break;

        case CHGMDP:
            //copier le fichier (au cas où), en supprimer un, en recréer un comme il faut
            //Bon en vrai il faudrait faire ça, TODO plus tard

            printf("Vous allez changer le mot de passe LightPAW\n");

            int c;
            char *new_pwd = (char*)calloc(56, sizeof(char));

            printf("Rentrez le nouveau mot de passe LightPAW (max 55 caractères) :\n");
            scanf("%55s", new_pwd);

            if((c = fgetc(stdin)) != '\n' && c != EOF) {
                //plus de 55 caractères
                printf("max 55 chars ! Do it again\n");
            } else {
                change_encryption(fd_file, new_pwd);
                printf("Mot de passe changé.\n");
            }

            break;

        case QUIT:
            menu = 0;
            break;
        
        default:
            printf("Je ne reconnais pas cette option...\n");
            break;
        }

        int c;
        while((c = fgetc(stdin)) != '\n' && c != EOF);
        getchar();
    }


    return 0;
}